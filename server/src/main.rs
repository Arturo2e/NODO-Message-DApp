mod eip712;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sqlx::{mysql::MySqlPoolOptions, MySqlPool, Row};
use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::{limit::RequestBodyLimitLayer, services::ServeDir, trace::TraceLayer};
use tracing::error;
use uuid::Uuid;

const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 96 * 1024;
const MAX_ONE_TIME_PREKEYS: usize = 200;
const MAX_PENDING_ENVELOPES_PER_DEVICE: i64 = 250;
const MAX_BUNDLE_KEY_BYTES: usize = 256;
const IDENTITY_PREKEY_ID: &str = "nodo-curve-identity-v1";
const BUNDLE_DOMAIN: &[u8] = b"NODO/OLM/PREKEY/v1\0";
const DEVICE_IDENTITY_DOMAIN: &[u8] = b"NODO/OLM/DEVICE-IDENTITY/v1\0";
const CHALLENGE_TTL_SECONDS: i64 = 5 * 60;
const IDENTITY_BINDING_TTL_SECONDS: i64 = 365 * 24 * 60 * 60;
const PREKEY_CLAIM_TTL_SECONDS: i64 = 15 * 60;
const SESSION_TTL_SECONDS: i64 = 12 * 60 * 60;
const ENVELOPE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const PRESENCE_TTL_SECONDS: i64 = 45;
const ENVELOPE_CLEANUP_INTERVAL_SECONDS: u64 = 60 * 60;

#[derive(Clone)]
struct AppState {
    pool: MySqlPool,
    limiter: Arc<RateLimiter>,
}

struct RateLimiter {
    windows: Mutex<HashMap<String, RateWindow>>,
}

struct RateWindow {
    started: SystemTime,
    count: u32,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, key: String, max: u32, window: Duration) -> Result<(), AppError> {
        let now = SystemTime::now();
        let mut windows = self.windows.lock().map_err(|_| AppError::Internal)?;
        if windows.len() > 50_000 {
            windows
                .retain(|_, entry| now.duration_since(entry.started).unwrap_or_default() < window);
        }
        let entry = windows.entry(key).or_insert(RateWindow {
            started: now,
            count: 0,
        });
        if now.duration_since(entry.started).unwrap_or_default() >= window {
            entry.started = now;
            entry.count = 0;
        }
        if entry.count >= max {
            return Err(AppError::RateLimited);
        }
        entry.count += 1;
        Ok(())
    }
}

#[derive(Debug, Error)]
enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("rate limited")]
    RateLimited,
    #[error("recipient mailbox is full")]
    MailboxFull,
    #[error("internal server error")]
    Internal,
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        error!(%error, "relay database operation failed");
        Self::Internal
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required".to_string(),
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "not allowed".to_string(),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found".to_string(),
            ),
            Self::Conflict(message) => (StatusCode::CONFLICT, "conflict", message),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "try again later".to_string(),
            ),
            Self::MailboxFull => (
                StatusCode::TOO_MANY_REQUESTS,
                "mailbox_full",
                "recipient mailbox is full; ask them to refresh or wait for expired messages"
                    .to_string(),
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error".to_string(),
            ),
        };
        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

#[derive(Clone, Debug)]
struct AuthContext {
    wallet: String,
    device_id: String,
    identity_key_hash: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ChallengeRequest {
    wallet: String,
    device_id: String,
    identity_key_hash: String,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    challenge_id: String,
    wallet: String,
    device_id: String,
    identity_key_hash: String,
    nonce: String,
    expires_at: u64,
    binding_expires_at: u64,
    signature: String,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    access_token: String,
    token_type: &'static str,
    expires_at: i64,
    wallet: String,
    device_id: String,
}

#[derive(Debug, Deserialize)]
struct KeyInput {
    key_id: String,
    public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct RegisterDeviceRequest {
    device_id: String,
    identity_key_hash: String,
    identity_key: String,
    binding_nonce: String,
    binding_expires_at: u64,
    binding_signature: String,
    signed_prekey: KeyInput,
    #[serde(default)]
    one_time_prekeys: Vec<KeyInput>,
}

#[derive(Debug, Serialize)]
struct SignedPrekeyResponse {
    key_id: String,
    public_key: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct DeviceBundleResponse {
    wallet: String,
    device_id: String,
    identity_key_hash: String,
    identity_key: String,
    binding_nonce: String,
    binding_expires_at: i64,
    binding_signature: String,
    signed_prekey: SignedPrekeyResponse,
    available_one_time_prekeys: i64,
}

#[derive(Debug, Serialize)]
struct BundlesResponse {
    wallet: String,
    devices: Vec<DeviceBundleResponse>,
}

#[derive(Debug, Serialize)]
struct ClaimedPrekeyResponse {
    wallet: String,
    device_id: String,
    key_id: String,
    public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct SendEnvelopeRequest {
    recipient_wallet: String,
    recipient_device_id: String,
    envelope_id: String,
    ciphertext: String,
    #[serde(default)]
    prekey_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct SendEnvelopeResponse {
    envelope_id: String,
    expires_at: i64,
    recipient_online: bool,
}

#[derive(Debug, Deserialize)]
struct ClaimPrekeyRequest {
    envelope_id: String,
}

#[derive(Debug, Deserialize)]
struct InboxQuery {
    limit: Option<u16>,
    before: Option<i64>,
}

#[derive(Debug, Serialize)]
struct InboxEnvelopeResponse {
    envelope_id: String,
    sender_wallet: String,
    sender_device_id: String,
    prekey_id: Option<String>,
    ciphertext: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct AckRequest {
    acknowledgments: Vec<DeliveryAcknowledgment>,
}

#[derive(Debug, Deserialize)]
struct DeliveryAcknowledgment {
    envelope_id: String,
    outcome: String,
    ciphertext_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct AckResponse {
    acknowledged: u64,
}

#[derive(Debug, Deserialize)]
struct PresenceTarget {
    wallet: String,
    device_id: String,
}

#[derive(Debug, Serialize)]
struct PresenceResponse {
    online: bool,
    expires_at: i64,
    checked_at: i64,
}

#[derive(Debug, Deserialize)]
struct DeliveryStatusRequest {
    envelope_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DeliveryStatusRecord {
    envelope_id: String,
    status: String,
    delivered_at: Option<i64>,
    expires_at: i64,
    ciphertext_hash: Option<String>,
    recipient_online: bool,
}

#[derive(Debug, Serialize)]
struct DeliveryStatusResponse {
    statuses: Vec<DeliveryStatusRecord>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be supplied at runtime")?;
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await?;
    sqlx::migrate!("../migrations").run(&pool).await?;

    let state = AppState {
        pool,
        limiter: Arc::new(RateLimiter::new()),
    };
    let cleanup_pool = state.pool.clone();
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(ENVELOPE_CLEANUP_INTERVAL_SECONDS));
        loop {
            interval.tick().await;
            if let Err(error) = purge_expired_envelopes(&cleanup_pool).await {
                tracing::error!(%error, "Could not purge expired NODO ciphertext envelopes");
            }
            if let Err(error) = purge_expired_auth_records(&cleanup_pool).await {
                tracing::error!(%error, "Could not purge expired NODO authentication records");
            }
        }
    });
    let app = router(state);
    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(3000);
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "NODO relay listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    let web_root = std::env::var("WEB_ROOT").unwrap_or_else(|_| "dist/public".to_string());
    Router::new()
        .route("/_app/health", get(health))
        .route("/v1/auth/challenge", post(create_challenge))
        .route("/v1/auth/verify", post(verify_challenge))
        .route("/v1/devices", post(register_device))
        .route("/v1/bundles/{wallet}", get(public_bundles))
        .route(
            "/v1/bundles/{wallet}/{device_id}/one-time-prekeys/claim",
            post(claim_one_time_prekey),
        )
        .route("/v1/messages", post(send_envelope))
        .route("/v1/messages/status", post(read_delivery_status))
        .route("/v1/inbox", get(read_inbox))
        .route("/v1/inbox/ack", post(ack_inbox))
        .route("/v1/presence/heartbeat", post(presence_heartbeat))
        .route("/v1/presence/offline", post(presence_offline))
        .route("/v1/presence/check", post(check_presence))
        .fallback_service(ServeDir::new(web_root).append_index_html_on_directories(true))
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .layer(TraceLayer::new_for_http())
}

async fn security_headers(
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        "nosniff".parse().expect("static header"),
    );
    headers.insert("cache-control", "no-store".parse().expect("static header"));
    response
}

async fn health(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<Value>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "health"), 120, Duration::from_secs(60))?;
    sqlx::query("SELECT 1").execute(&state.pool).await?;
    Ok(Json(json!({ "status": "ok" })))
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn envelope_is_expired(expires_at: i64, now: i64) -> bool {
    expires_at <= now
}

fn existing_ciphertext_matches(
    stored_hash: Option<&[u8]>,
    stored_ciphertext: &[u8],
    requested_hash: &[u8],
    requested_ciphertext: &[u8],
) -> bool {
    match stored_hash {
        Some(hash) => hash == requested_hash,
        None => !stored_ciphertext.is_empty() && stored_ciphertext == requested_ciphertext,
    }
}

async fn purge_expired_envelopes(pool: &MySqlPool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM relay_envelopes WHERE expires_at <= ?")
        .bind(now_seconds())
        .execute(pool)
        .await
        .map(|_| ())
}

async fn purge_expired_auth_records(pool: &MySqlPool) -> Result<(), sqlx::Error> {
    let now = now_seconds();
    sqlx::query("DELETE FROM relay_challenges WHERE expires_at <= ? LIMIT 5000")
        .bind(now)
        .execute(pool)
        .await?;
    sqlx::query(
        "DELETE FROM relay_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL LIMIT 5000",
    )
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

fn normalized_address(value: &str) -> Result<String, AppError> {
    let raw = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| {
            AppError::BadRequest("wallet must be a 20-byte 0x-prefixed address".into())
        })?;
    if raw.len() != 40 || !raw.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(AppError::BadRequest(
            "wallet must be a 20-byte 0x-prefixed address".into(),
        ));
    }
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

fn normalized_device(value: &str) -> Result<String, AppError> {
    Uuid::parse_str(value)
        .map(|uuid| uuid.hyphenated().to_string())
        .map_err(|_| AppError::BadRequest("device_id must be a UUID".into()))
}

fn normalized_uuid(value: &str, field: &str) -> Result<String, AppError> {
    Uuid::parse_str(value)
        .map(|uuid| uuid.hyphenated().to_string())
        .map_err(|_| AppError::BadRequest(format!("{field} must be a UUID")))
}

fn normalized_envelope_id(value: &str) -> Result<String, AppError> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| AppError::BadRequest("envelope_id must be a UUIDv4".into()))?;
    let bytes = uuid.as_bytes();
    if bytes[6] & 0xf0 != 0x40 || bytes[8] & 0xc0 != 0x80 {
        return Err(AppError::BadRequest(
            "envelope_id must be an RFC 4122 UUIDv4".into(),
        ));
    }
    Ok(uuid.hyphenated().to_string())
}

fn parse_hash(value: &str, field: &str) -> Result<[u8; 32], AppError> {
    let raw = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| AppError::BadRequest(format!("{field} must be a 32-byte hex value")))?;
    if raw.len() != 64 {
        return Err(AppError::BadRequest(format!(
            "{field} must be a 32-byte hex value"
        )));
    }
    let bytes = hex::decode(raw)
        .map_err(|_| AppError::BadRequest(format!("{field} must be a 32-byte hex value")))?;
    let mut output = [0_u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn decode_key(value: &str, field: &str) -> Result<Vec<u8>, AppError> {
    if value.len() > MAX_BUNDLE_KEY_BYTES * 2 {
        return Err(AppError::BadRequest(format!("{field} is too large")));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::BadRequest(format!("{field} must be unpadded base64url")))?;
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_KEY_BYTES {
        return Err(AppError::BadRequest(format!("{field} has an invalid size")));
    }
    Ok(bytes)
}

fn encode_key(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn sha256_bytes(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn rate_key(addr: SocketAddr, route: &str) -> String {
    format!("{}:{route}", addr.ip())
}

async fn create_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<Value>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "challenge"), 20, Duration::from_secs(60))?;
    let wallet = normalized_address(&request.wallet)?;
    let device_id = normalized_device(&request.device_id)?;
    let identity_key_hash = parse_hash(&request.identity_key_hash, "identity_key_hash")?;
    let challenge_id = Uuid::new_v4().hyphenated().to_string();
    let nonce = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
    let now = now_seconds();
    let expires_at = now.saturating_add(CHALLENGE_TTL_SECONDS);
    let binding_expires_at = now.saturating_add(IDENTITY_BINDING_TTL_SECONDS);
    sqlx::query(
        "INSERT INTO relay_challenges (challenge_id, wallet_address, device_id, identity_key_hash, nonce_hash, expires_at, binding_expires_at, created_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(&challenge_id)
    .bind(&wallet)
    .bind(&device_id)
    .bind(identity_key_hash.to_vec())
    .bind(sha256_bytes(nonce.as_bytes()))
    .bind(expires_at)
    .bind(binding_expires_at)
    .bind(now_seconds())
    .execute(&state.pool)
    .await?;

    let typed_data = typed_data_json(
        &wallet,
        &device_id,
        &identity_key_hash,
        &nonce,
        binding_expires_at as u64,
    );
    Ok(Json(json!({
        "challenge_id": challenge_id,
        "nonce": nonce,
        "expires_at": expires_at,
        "binding_expires_at": binding_expires_at,
        "typed_data": typed_data,
    })))
}

fn typed_data_json(
    wallet: &str,
    device_id: &str,
    identity_key_hash: &[u8; 32],
    nonce: &str,
    expires_at: u64,
) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" }
            ],
            "IdentityKeyBinding": [
                { "name": "wallet", "type": "address" },
                { "name": "deviceId", "type": "string" },
                { "name": "identityKeyHash", "type": "bytes32" },
                { "name": "nonce", "type": "string" },
                { "name": "expiresAt", "type": "uint64" }
            ]
        },
        "primaryType": "IdentityKeyBinding",
        "domain": {
            "name": "NODO Secure Messaging",
            "version": "1",
            "chainId": 11155111_u64
        },
        "message": {
            "wallet": wallet,
            "deviceId": device_id,
            "identityKeyHash": format!("0x{}", hex::encode(identity_key_hash)),
            "nonce": nonce,
            "expiresAt": expires_at
        }
    })
}

async fn verify_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<SessionResponse>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "verify"), 20, Duration::from_secs(60))?;
    let challenge_id = normalized_uuid(&request.challenge_id, "challenge_id")?;
    let wallet = normalized_address(&request.wallet)?;
    let device_id = normalized_device(&request.device_id)?;
    let identity_key_hash = parse_hash(&request.identity_key_hash, "identity_key_hash")?;
    if request.expires_at > i64::MAX as u64
        || request.binding_expires_at > i64::MAX as u64
        || request.nonce.len() > 256
    {
        return Err(AppError::Unauthorized);
    }
    let now = now_seconds();
    let binding_expires_at = request.binding_expires_at as i64;
    if binding_expires_at <= now
        || binding_expires_at > now.saturating_add(IDENTITY_BINDING_TTL_SECONDS)
    {
        return Err(AppError::Unauthorized);
    }
    let challenge = sqlx::query(
        "SELECT wallet_address, device_id, identity_key_hash, nonce_hash, expires_at, binding_expires_at FROM relay_challenges WHERE challenge_id = ? AND consumed_at IS NULL",
    )
    .bind(&challenge_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;
    let stored_wallet: String = challenge.try_get("wallet_address")?;
    let stored_device: String = challenge.try_get("device_id")?;
    let stored_identity: Vec<u8> = challenge.try_get("identity_key_hash")?;
    let stored_nonce_hash: Vec<u8> = challenge.try_get("nonce_hash")?;
    let stored_expires_at: i64 = challenge.try_get("expires_at")?;
    let stored_binding_expires_at: i64 = challenge.try_get("binding_expires_at")?;
    if stored_wallet != wallet
        || stored_device != device_id
        || stored_identity.as_slice() != identity_key_hash
        || stored_nonce_hash.as_slice() != sha256_bytes(request.nonce.as_bytes()).as_slice()
        || stored_expires_at != request.expires_at as i64
        || stored_binding_expires_at != request.binding_expires_at as i64
        || stored_expires_at <= now_seconds()
    {
        return Err(AppError::Unauthorized);
    }
    let recovered = eip712::recover_wallet(
        &wallet,
        &device_id,
        &identity_key_hash,
        &request.nonce,
        request.binding_expires_at,
        &request.signature,
    )
    .map_err(|_| AppError::Unauthorized)?;
    if recovered != wallet {
        return Err(AppError::Unauthorized);
    }

    let token = random_bytes::<32>();
    let token_text = URL_SAFE_NO_PAD.encode(token);
    let token_hash = sha256_bytes(&token);
    let session_expires_at = now_seconds().saturating_add(SESSION_TTL_SECONDS);
    let mut transaction = state.pool.begin().await?;
    let consumed = sqlx::query("UPDATE relay_challenges SET consumed_at = ? WHERE challenge_id = ? AND consumed_at IS NULL")
        .bind(now_seconds())
        .bind(&challenge_id)
        .execute(&mut *transaction)
        .await?;
    if consumed.rows_affected() != 1 {
        transaction.rollback().await?;
        return Err(AppError::Conflict("challenge was already used".into()));
    }
    sqlx::query(
        "INSERT INTO relay_sessions (token_hash, wallet_address, device_id, identity_key_hash, expires_at, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(token_hash)
    .bind(&wallet)
    .bind(&device_id)
    .bind(identity_key_hash.to_vec())
    .bind(session_expires_at)
    .bind(now_seconds())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(SessionResponse {
        access_token: token_text,
        token_type: "Bearer",
        expires_at: session_expires_at,
        wallet,
        device_id,
    }))
}

async fn authenticated_session(
    headers: &HeaderMap,
    pool: &MySqlPool,
) -> Result<AuthContext, AppError> {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    if token.len() > 256 {
        return Err(AppError::Unauthorized);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| AppError::Unauthorized)?;
    if raw.len() != 32 {
        return Err(AppError::Unauthorized);
    }
    let token_hash = sha256_bytes(&raw);
    let row = sqlx::query(
        "SELECT wallet_address, device_id, identity_key_hash FROM relay_sessions WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(token_hash)
    .bind(now_seconds())
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::Unauthorized)?;
    Ok(AuthContext {
        wallet: row.try_get("wallet_address")?,
        device_id: row.try_get("device_id")?,
        identity_key_hash: row.try_get("identity_key_hash")?,
    })
}

async fn register_device(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<Json<Value>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "register"), 30, Duration::from_secs(60))?;
    let auth = authenticated_session(&headers, &state.pool).await?;
    let device_id = normalized_device(&request.device_id)?;
    let identity_key_hash = parse_hash(&request.identity_key_hash, "identity_key_hash")?;
    if device_id != auth.device_id
        || identity_key_hash.as_slice() != auth.identity_key_hash.as_slice()
    {
        return Err(AppError::Forbidden);
    }
    if request.binding_nonce.is_empty() || request.binding_nonce.len() > 256 {
        return Err(AppError::BadRequest(
            "binding_nonce must be a non-empty value of at most 256 bytes".into(),
        ));
    }
    let binding_expires_at = i64::try_from(request.binding_expires_at).map_err(|_| {
        AppError::BadRequest("binding_expires_at must be a valid signed challenge expiry".into())
    })?;
    let now = now_seconds();
    if binding_expires_at <= now
        || binding_expires_at > now.saturating_add(IDENTITY_BINDING_TTL_SECONDS)
    {
        return Err(AppError::BadRequest(
            "binding_expires_at must be within the signed identity-binding lifetime".into(),
        ));
    }
    let recovered = eip712::recover_wallet(
        &auth.wallet,
        &device_id,
        &identity_key_hash,
        &request.binding_nonce,
        request.binding_expires_at,
        &request.binding_signature,
    )
    .map_err(|_| AppError::Forbidden)?;
    if recovered != auth.wallet {
        return Err(AppError::Forbidden);
    }
    if request.one_time_prekeys.len() > MAX_ONE_TIME_PREKEYS {
        return Err(AppError::BadRequest("too many one-time prekeys".into()));
    }
    let identity_key = decode_key(&request.identity_key, "identity_key")?;
    if identity_key.len() != 32 {
        return Err(AppError::BadRequest(
            "identity_key must be a 32-byte Ed25519 public key".into(),
        ));
    }
    if sha256_bytes(&identity_key).as_slice() != identity_key_hash {
        return Err(AppError::BadRequest(
            "identity_key_hash does not match identity_key".into(),
        ));
    }
    if request.signed_prekey.key_id != IDENTITY_PREKEY_ID {
        return Err(AppError::BadRequest(
            "signed_prekey.key_id is not the expected device identity key ID".into(),
        ));
    }
    let signed_prekey = validate_key_input(request.signed_prekey, "signed_prekey")?;
    let mut device_identity_message =
        Vec::with_capacity(DEVICE_IDENTITY_DOMAIN.len() + signed_prekey.public_key.len());
    device_identity_message.extend_from_slice(DEVICE_IDENTITY_DOMAIN);
    device_identity_message.extend_from_slice(&signed_prekey.public_key);
    verify_ed25519_signature(
        &identity_key,
        &device_identity_message,
        &signed_prekey.signature,
        "signed_prekey.signature",
    )?;
    let mut one_time_prekeys = Vec::with_capacity(request.one_time_prekeys.len());
    let mut seen_prekey_ids = BTreeSet::new();
    for item in request.one_time_prekeys {
        let prekey = validate_key_input(item, "one_time_prekey")?;
        let expected_id = format!("otk-{}", hex::encode(sha256_bytes(&prekey.public_key)));
        if prekey.key_id != expected_id || !seen_prekey_ids.insert(prekey.key_id.clone()) {
            return Err(AppError::BadRequest(
                "one_time_prekey key_id is invalid or duplicated".into(),
            ));
        }
        let mut bundle_message = Vec::with_capacity(
            BUNDLE_DOMAIN.len() + signed_prekey.public_key.len() + prekey.public_key.len(),
        );
        bundle_message.extend_from_slice(BUNDLE_DOMAIN);
        bundle_message.extend_from_slice(&signed_prekey.public_key);
        bundle_message.extend_from_slice(&prekey.public_key);
        verify_ed25519_signature(
            &identity_key,
            &bundle_message,
            &prekey.signature,
            "one_time_prekey.signature",
        )?;
        one_time_prekeys.push(prekey);
    }

    let mut transaction = state.pool.begin().await?;
    let existing = sqlx::query("SELECT identity_key_hash FROM relay_devices WHERE wallet_address = ? AND device_id = ? FOR UPDATE")
        .bind(&auth.wallet)
        .bind(&device_id)
        .fetch_optional(&mut *transaction)
        .await?;
    if let Some(row) = existing {
        let old_hash: Vec<u8> = row.try_get("identity_key_hash")?;
        if old_hash.as_slice() != identity_key_hash {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "device identity key cannot be changed; use a new device_id".into(),
            ));
        }
        sqlx::query("UPDATE relay_devices SET binding_nonce = ?, binding_expires_at = ?, binding_signature = ?, identity_public_key = ?, signed_prekey_id = ?, signed_prekey_public_key = ?, signed_prekey_signature = ?, updated_at = ? WHERE wallet_address = ? AND device_id = ?")
            .bind(&request.binding_nonce)
            .bind(binding_expires_at)
            .bind(&request.binding_signature)
            .bind(identity_key.clone())
            .bind(&signed_prekey.key_id)
            .bind(signed_prekey.public_key.clone())
            .bind(signed_prekey.signature.clone())
            .bind(now_seconds())
            .bind(&auth.wallet)
            .bind(&device_id)
            .execute(&mut *transaction)
            .await?;
    } else {
        sqlx::query("INSERT INTO relay_devices (wallet_address, device_id, identity_key_hash, binding_nonce, binding_expires_at, binding_signature, identity_public_key, signed_prekey_id, signed_prekey_public_key, signed_prekey_signature, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&auth.wallet)
            .bind(&device_id)
            .bind(identity_key_hash.to_vec())
            .bind(&request.binding_nonce)
            .bind(binding_expires_at)
            .bind(&request.binding_signature)
            .bind(identity_key.clone())
            .bind(&signed_prekey.key_id)
            .bind(signed_prekey.public_key.clone())
            .bind(signed_prekey.signature.clone())
            .bind(now_seconds())
            .bind(now_seconds())
            .execute(&mut *transaction)
            .await?;
    }
    for prekey in one_time_prekeys {
        sqlx::query("INSERT IGNORE INTO relay_one_time_prekeys (wallet_address, device_id, key_id, public_key, signature, created_at, claimed_at, claimed_by_wallet, claimed_by_device) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)")
            .bind(&auth.wallet)
            .bind(&device_id)
            .bind(&prekey.key_id)
            .bind(prekey.public_key)
            .bind(prekey.signature)
            .bind(now_seconds())
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(Json(
        json!({ "wallet": auth.wallet, "device_id": device_id, "registered": true }),
    ))
}

struct ValidatedKey {
    key_id: String,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

fn validate_key_input(input: KeyInput, field: &str) -> Result<ValidatedKey, AppError> {
    if input.key_id.is_empty() || input.key_id.len() > 128 || !input.key_id.is_ascii() {
        return Err(AppError::BadRequest(format!("{field}.key_id is invalid")));
    }
    let public_key = decode_key(&input.public_key, &format!("{field}.public_key"))?;
    if public_key.len() != 32 {
        return Err(AppError::BadRequest(format!(
            "{field}.public_key must be a 32-byte Curve25519 key"
        )));
    }
    let signature = decode_key(&input.signature, &format!("{field}.signature"))?;
    if signature.len() != 64 {
        return Err(AppError::BadRequest(format!(
            "{field}.signature must be a 64-byte Ed25519 signature"
        )));
    }
    Ok(ValidatedKey {
        key_id: input.key_id,
        public_key,
        signature,
    })
}

fn verify_ed25519_signature(
    identity_key: &[u8],
    message: &[u8],
    signature: &[u8],
    field: &str,
) -> Result<(), AppError> {
    UnparsedPublicKey::new(&ED25519, identity_key)
        .verify(message, signature)
        .map_err(|_| {
            AppError::BadRequest(format!("{field} is not signed by the device identity key"))
        })
}

async fn public_bundles(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(wallet): Path<String>,
) -> Result<Json<BundlesResponse>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "bundles"), 120, Duration::from_secs(60))?;
    let wallet = normalized_address(&wallet)?;
    let rows = sqlx::query("SELECT device_id, identity_key_hash, identity_public_key, binding_nonce, binding_expires_at, binding_signature, signed_prekey_id, signed_prekey_public_key, signed_prekey_signature FROM relay_devices WHERE wallet_address = ? ORDER BY device_id")
        .bind(&wallet)
        .fetch_all(&state.pool)
        .await?;
    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        let device_id: String = row.try_get("device_id")?;
        let available: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relay_one_time_prekeys WHERE wallet_address = ? AND device_id = ? AND (claimed_at IS NULL OR (used_by_envelope_id IS NULL AND claim_expires_at <= ?))")
            .bind(&wallet)
            .bind(&device_id)
            .bind(now_seconds())
            .fetch_one(&state.pool)
            .await?;
        let identity_hash: Vec<u8> = row.try_get("identity_key_hash")?;
        let identity_key: Vec<u8> = row.try_get("identity_public_key")?;
        let signed_key: Vec<u8> = row.try_get("signed_prekey_public_key")?;
        let signed_signature: Vec<u8> = row.try_get("signed_prekey_signature")?;
        devices.push(DeviceBundleResponse {
            wallet: wallet.clone(),
            device_id,
            identity_key_hash: format!("0x{}", hex::encode(identity_hash)),
            identity_key: encode_key(&identity_key),
            binding_nonce: row.try_get("binding_nonce")?,
            binding_expires_at: row.try_get("binding_expires_at")?,
            binding_signature: row.try_get("binding_signature")?,
            signed_prekey: SignedPrekeyResponse {
                key_id: row.try_get("signed_prekey_id")?,
                public_key: encode_key(&signed_key),
                signature: encode_key(&signed_signature),
            },
            available_one_time_prekeys: available,
        });
    }
    Ok(Json(BundlesResponse { wallet, devices }))
}

async fn claim_one_time_prekey(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((wallet, device_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<ClaimPrekeyRequest>,
) -> Result<Json<ClaimedPrekeyResponse>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "claim-prekey"), 60, Duration::from_secs(60))?;
    let auth = authenticated_session(&headers, &state.pool).await?;
    let wallet = normalized_address(&wallet)?;
    let device_id = normalized_device(&device_id)?;
    let envelope_id = normalized_envelope_id(&request.envelope_id)?;
    let now = now_seconds();
    let claim_expires_at = now.saturating_add(PREKEY_CLAIM_TTL_SECONDS);
    let mut transaction = state.pool.begin().await?;

    let existing_claim = sqlx::query("SELECT key_id, public_key, signature FROM relay_one_time_prekeys WHERE wallet_address = ? AND device_id = ? AND claimed_by_wallet = ? AND claimed_by_device = ? AND claimed_envelope_id = ? AND used_by_envelope_id IS NULL AND claim_expires_at > ? LIMIT 1 FOR UPDATE")
        .bind(&wallet)
        .bind(&device_id)
        .bind(&auth.wallet)
        .bind(&auth.device_id)
        .bind(&envelope_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
    if let Some(row) = existing_claim {
        let response = ClaimedPrekeyResponse {
            wallet,
            device_id,
            key_id: row.try_get("key_id")?,
            public_key: encode_key(&row.try_get::<Vec<u8>, _>("public_key")?),
            signature: encode_key(&row.try_get::<Vec<u8>, _>("signature")?),
        };
        transaction.commit().await?;
        return Ok(Json(response));
    }

    let row = sqlx::query("SELECT key_id, public_key, signature FROM relay_one_time_prekeys WHERE wallet_address = ? AND device_id = ? AND (claimed_at IS NULL OR (used_by_envelope_id IS NULL AND claim_expires_at <= ?)) ORDER BY created_at, key_id LIMIT 1 FOR UPDATE")
        .bind(&wallet)
        .bind(&device_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AppError::NotFound)?;
    let key_id: String = row.try_get("key_id")?;
    let updated = sqlx::query("UPDATE relay_one_time_prekeys SET claimed_at = ?, claim_expires_at = ?, claimed_envelope_id = ?, claimed_by_wallet = ?, claimed_by_device = ?, used_by_envelope_id = NULL WHERE wallet_address = ? AND device_id = ? AND key_id = ? AND (claimed_at IS NULL OR (used_by_envelope_id IS NULL AND claim_expires_at <= ?))")
        .bind(now)
        .bind(claim_expires_at)
        .bind(&envelope_id)
        .bind(&auth.wallet)
        .bind(&auth.device_id)
        .bind(&wallet)
        .bind(&device_id)
        .bind(&key_id)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    if updated.rows_affected() != 1 {
        transaction.rollback().await?;
        return Err(AppError::Conflict(
            "one-time prekey was already claimed".into(),
        ));
    }
    transaction.commit().await?;
    Ok(Json(ClaimedPrekeyResponse {
        wallet,
        device_id,
        key_id,
        public_key: encode_key(&row.try_get::<Vec<u8>, _>("public_key")?),
        signature: encode_key(&row.try_get::<Vec<u8>, _>("signature")?),
    }))
}

async fn send_envelope(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SendEnvelopeRequest>,
) -> Result<Json<SendEnvelopeResponse>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "send"), 120, Duration::from_secs(60))?;
    let auth = authenticated_session(&headers, &state.pool).await?;
    purge_expired_envelopes(&state.pool).await?;
    let recipient_wallet = normalized_address(&request.recipient_wallet)?;
    let recipient_device_id = normalized_device(&request.recipient_device_id)?;
    let envelope_id = normalized_envelope_id(&request.envelope_id)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(request.ciphertext)
        .map_err(|_| AppError::BadRequest("ciphertext must be unpadded base64url".into()))?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(AppError::BadRequest(
            "ciphertext is empty or too large".into(),
        ));
    }
    let ciphertext_hash = Keccak256::digest(&ciphertext).to_vec();
    let prekey_id = request
        .prekey_id
        .map(|value| {
            if value.is_empty() || value.len() > 128 || !value.is_ascii() {
                Err(AppError::BadRequest("prekey_id is invalid".into()))
            } else {
                Ok(value)
            }
        })
        .transpose()?;
    let mut transaction = state.pool.begin().await?;
    let recipient_exists = sqlx::query(
        "SELECT device_id, presence_until FROM relay_devices WHERE wallet_address = ? AND device_id = ? FOR UPDATE",
    )
    .bind(&recipient_wallet)
    .bind(&recipient_device_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let recipient_row = recipient_exists.ok_or(AppError::NotFound)?;
    let recipient_online = recipient_row.try_get::<i64, _>("presence_until")? > now_seconds();

    let existing = sqlx::query("SELECT sender_wallet, sender_device_id, recipient_wallet, recipient_device_id, prekey_id, expires_at, ciphertext, ciphertext_hash FROM relay_envelopes WHERE envelope_id = ?")
        .bind(&envelope_id)
        .fetch_optional(&mut *transaction)
        .await?;
    if let Some(row) = existing {
        let stored_hash: Option<Vec<u8>> = row.try_get("ciphertext_hash")?;
        let stored_ciphertext: Vec<u8> = row.try_get("ciphertext")?;
        let same_ciphertext = existing_ciphertext_matches(
            stored_hash.as_deref(),
            &stored_ciphertext,
            &ciphertext_hash,
            &ciphertext,
        );
        let same_request = row.try_get::<String, _>("sender_wallet")? == auth.wallet
            && row.try_get::<String, _>("sender_device_id")? == auth.device_id
            && row.try_get::<String, _>("recipient_wallet")? == recipient_wallet
            && row.try_get::<String, _>("recipient_device_id")? == recipient_device_id
            && row.try_get::<Option<String>, _>("prekey_id")? == prekey_id
            && same_ciphertext;
        if !same_request {
            transaction.rollback().await?;
            return Err(AppError::Conflict("envelope_id was already used".into()));
        }
        let expires_at: i64 = row.try_get("expires_at")?;
        if envelope_is_expired(expires_at, now_seconds()) {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "envelope_id has expired and cannot be replayed".into(),
            ));
        }
        transaction.commit().await?;
        return Ok(Json(SendEnvelopeResponse {
            envelope_id,
            expires_at,
            recipient_online,
        }));
    }

    let reserved_id = sqlx::query("INSERT IGNORE INTO relay_envelope_ids (envelope_id) VALUES (?)")
        .bind(&envelope_id)
        .execute(&mut *transaction)
        .await?;
    if reserved_id.rows_affected() != 1 {
        transaction.rollback().await?;
        return Err(AppError::Conflict(
            "envelope_id was already used or expired".into(),
        ));
    }

    let now = now_seconds();
    let pending_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relay_envelopes WHERE recipient_wallet = ? AND recipient_device_id = ? AND delivered_at IS NULL AND expires_at > ?")
        .bind(&recipient_wallet)
        .bind(&recipient_device_id)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await?;
    if pending_count >= MAX_PENDING_ENVELOPES_PER_DEVICE {
        transaction.rollback().await?;
        return Err(AppError::MailboxFull);
    }

    if let Some(prekey_id) = prekey_id.as_deref() {
        let claim = sqlx::query("SELECT claimed_by_wallet, claimed_by_device, claimed_envelope_id, claim_expires_at, used_by_envelope_id FROM relay_one_time_prekeys WHERE wallet_address = ? AND device_id = ? AND key_id = ? FOR UPDATE")
            .bind(&recipient_wallet)
            .bind(&recipient_device_id)
            .bind(prekey_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(AppError::BadRequest("prekey_id is unknown".into()))?;
        let claimed_wallet: Option<String> = claim.try_get("claimed_by_wallet")?;
        let claimed_device: Option<String> = claim.try_get("claimed_by_device")?;
        let claimed_envelope: Option<String> = claim.try_get("claimed_envelope_id")?;
        let claim_expires_at: Option<i64> = claim.try_get("claim_expires_at")?;
        let used_by_envelope: Option<String> = claim.try_get("used_by_envelope_id")?;
        if claimed_wallet.as_deref() != Some(auth.wallet.as_str())
            || claimed_device.as_deref() != Some(auth.device_id.as_str())
        {
            transaction.rollback().await?;
            return Err(AppError::Forbidden);
        }
        if claimed_envelope.as_deref() != Some(envelope_id.as_str()) {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "one-time prekey is reserved for a different envelope".into(),
            ));
        }
        if used_by_envelope.as_deref() == Some(envelope_id.as_str()) {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "the initial envelope has already expired".into(),
            ));
        }
        if used_by_envelope.is_some() || claim_expires_at.is_none_or(|expires| expires <= now) {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "one-time prekey claim expired or was already consumed".into(),
            ));
        }
        let consumed = sqlx::query("UPDATE relay_one_time_prekeys SET used_by_envelope_id = ?, claim_expires_at = NULL WHERE wallet_address = ? AND device_id = ? AND key_id = ? AND claimed_envelope_id = ? AND used_by_envelope_id IS NULL AND claim_expires_at > ?")
            .bind(&envelope_id)
            .bind(&recipient_wallet)
            .bind(&recipient_device_id)
            .bind(prekey_id)
            .bind(&envelope_id)
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        if consumed.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "one-time prekey claim expired or was already consumed".into(),
            ));
        }
    }

    let expires_at = now.saturating_add(ENVELOPE_TTL_SECONDS);
    let result = sqlx::query("INSERT INTO relay_envelopes (envelope_id, sender_wallet, sender_device_id, recipient_wallet, recipient_device_id, prekey_id, ciphertext, created_at, expires_at, delivered_at, ciphertext_hash, delivery_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, 'queued')")
        .bind(&envelope_id)
        .bind(&auth.wallet)
        .bind(&auth.device_id)
        .bind(&recipient_wallet)
        .bind(&recipient_device_id)
        .bind(prekey_id)
        .bind(ciphertext)
        .bind(now)
        .bind(expires_at)
        .bind(ciphertext_hash)
        .execute(&mut *transaction)
        .await;
    match result {
        Ok(_) => {
            transaction.commit().await?;
            Ok(Json(SendEnvelopeResponse {
                envelope_id,
                expires_at,
                recipient_online,
            }))
        }
        Err(error)
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("1062") =>
        {
            transaction.rollback().await?;
            Err(AppError::Conflict("envelope_id was already used".into()))
        }
        Err(error) => {
            transaction.rollback().await?;
            Err(error.into())
        }
    }
}

async fn read_inbox(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<InboxQuery>,
) -> Result<Json<Vec<InboxEnvelopeResponse>>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "inbox"), 120, Duration::from_secs(60))?;
    let auth = authenticated_session(&headers, &state.pool).await?;
    purge_expired_envelopes(&state.pool).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let now = now_seconds();
    let presence_until: Option<i64> = sqlx::query_scalar(
        "SELECT presence_until FROM relay_devices WHERE wallet_address = ? AND device_id = ? AND identity_key_hash = ?",
    )
    .bind(&auth.wallet)
    .bind(&auth.device_id)
    .bind(&auth.identity_key_hash)
    .fetch_optional(&state.pool)
    .await?;
    if presence_until.is_none_or(|expires_at| expires_at <= now) {
        return Err(AppError::Conflict(
            "presence lease expired; renew presence before reading the inbox".into(),
        ));
    }
    let rows = if let Some(before) = query.before {
        let statement = format!("SELECT envelope_id, sender_wallet, sender_device_id, prekey_id, ciphertext, created_at, expires_at FROM relay_envelopes WHERE recipient_wallet = ? AND recipient_device_id = ? AND delivered_at IS NULL AND expires_at > ? AND created_at < ? ORDER BY created_at DESC LIMIT {limit}");
        sqlx::query(&statement)
            .bind(&auth.wallet)
            .bind(&auth.device_id)
            .bind(now)
            .bind(before)
            .fetch_all(&state.pool)
            .await?
    } else {
        let statement = format!("SELECT envelope_id, sender_wallet, sender_device_id, prekey_id, ciphertext, created_at, expires_at FROM relay_envelopes WHERE recipient_wallet = ? AND recipient_device_id = ? AND delivered_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT {limit}");
        sqlx::query(&statement)
            .bind(&auth.wallet)
            .bind(&auth.device_id)
            .bind(now)
            .fetch_all(&state.pool)
            .await?
    };
    let envelopes = rows
        .into_iter()
        .map(|row| {
            Ok(InboxEnvelopeResponse {
                envelope_id: row.try_get("envelope_id")?,
                sender_wallet: row.try_get("sender_wallet")?,
                sender_device_id: row.try_get("sender_device_id")?,
                prekey_id: row.try_get("prekey_id")?,
                ciphertext: encode_key(&row.try_get::<Vec<u8>, _>("ciphertext")?),
                created_at: row.try_get("created_at")?,
                expires_at: row.try_get("expires_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(Json(envelopes))
}

async fn presence_heartbeat(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<PresenceResponse>, AppError> {
    state.limiter.check(
        rate_key(addr, "presence-heartbeat"),
        60,
        Duration::from_secs(60),
    )?;
    let auth = authenticated_session(&headers, &state.pool).await?;
    let now = now_seconds();
    let expires_at = now.saturating_add(PRESENCE_TTL_SECONDS);
    let updated = sqlx::query(
        "UPDATE relay_devices SET presence_until = ? WHERE wallet_address = ? AND device_id = ? AND identity_key_hash = ?",
    )
    .bind(expires_at)
    .bind(&auth.wallet)
    .bind(&auth.device_id)
    .bind(&auth.identity_key_hash)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(AppError::NotFound);
    }
    Ok(Json(PresenceResponse {
        online: true,
        expires_at,
        checked_at: now,
    }))
}

async fn presence_offline(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<PresenceResponse>, AppError> {
    state.limiter.check(
        rate_key(addr, "presence-offline"),
        30,
        Duration::from_secs(60),
    )?;
    let auth = authenticated_session(&headers, &state.pool).await?;
    let now = now_seconds();
    let updated = sqlx::query(
        "UPDATE relay_devices SET presence_until = 0 WHERE wallet_address = ? AND device_id = ? AND identity_key_hash = ?",
    )
    .bind(&auth.wallet)
    .bind(&auth.device_id)
    .bind(&auth.identity_key_hash)
    .execute(&state.pool)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(AppError::NotFound);
    }
    Ok(Json(PresenceResponse {
        online: false,
        expires_at: 0,
        checked_at: now,
    }))
}

async fn check_presence(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(target): Json<PresenceTarget>,
) -> Result<Json<PresenceResponse>, AppError> {
    state.limiter.check(
        rate_key(addr, "presence-check"),
        120,
        Duration::from_secs(60),
    )?;
    let _auth = authenticated_session(&headers, &state.pool).await?;
    let wallet = normalized_address(&target.wallet)?;
    let device_id = normalized_device(&target.device_id)?;
    let expires_at: Option<i64> = sqlx::query_scalar(
        "SELECT presence_until FROM relay_devices WHERE wallet_address = ? AND device_id = ?",
    )
    .bind(wallet)
    .bind(device_id)
    .fetch_optional(&state.pool)
    .await?;
    let now = now_seconds();
    let expires_at = expires_at.ok_or(AppError::NotFound)?;
    Ok(Json(PresenceResponse {
        online: expires_at > now,
        expires_at,
        checked_at: now,
    }))
}

fn ack_ciphertext_hash_matches(
    stored_hash: Option<&[u8]>,
    ciphertext: &[u8],
    supplied_hash: &[u8],
) -> bool {
    if ciphertext.is_empty() {
        return stored_hash.is_some_and(|stored| stored == supplied_hash);
    }
    let computed_hash = Keccak256::digest(ciphertext);
    stored_hash.is_none_or(|stored| stored == &computed_hash[..])
        && &computed_hash[..] == supplied_hash
}

async fn ack_inbox(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AckRequest>,
) -> Result<Json<AckResponse>, AppError> {
    state
        .limiter
        .check(rate_key(addr, "ack"), 120, Duration::from_secs(60))?;
    let auth = authenticated_session(&headers, &state.pool).await?;
    if request.acknowledgments.is_empty() || request.acknowledgments.len() > 100 {
        return Err(AppError::BadRequest(
            "acknowledgments must contain 1 to 100 values".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut acknowledgments = Vec::with_capacity(request.acknowledgments.len());
    for acknowledgment in request.acknowledgments {
        let envelope_id = normalized_envelope_id(&acknowledgment.envelope_id)?;
        if !seen.insert(envelope_id.clone()) {
            return Err(AppError::BadRequest(
                "acknowledgments must not contain duplicate envelope IDs".into(),
            ));
        }
        if acknowledgment.outcome != "delivered" && acknowledgment.outcome != "rejected" {
            return Err(AppError::BadRequest(
                "ack outcome must be delivered or rejected".into(),
            ));
        }
        let ciphertext_hash = acknowledgment.ciphertext_hash.as_deref().ok_or_else(|| {
            AppError::BadRequest("acknowledgments require a ciphertext hash".into())
        })?;
        let ciphertext_hash = parse_hash(ciphertext_hash, "ciphertext_hash")?;
        acknowledgments.push((envelope_id, acknowledgment.outcome, ciphertext_hash));
    }

    let mut transaction = state.pool.begin().await?;
    let mut acknowledged = 0_u64;
    for (envelope_id, outcome, supplied_hash) in acknowledgments {
        let row = sqlx::query(
            "SELECT delivery_status, ciphertext_hash, ciphertext, expires_at FROM relay_envelopes WHERE envelope_id = ? AND recipient_wallet = ? AND recipient_device_id = ? FOR UPDATE",
        )
        .bind(&envelope_id)
        .bind(&auth.wallet)
        .bind(&auth.device_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "envelope is no longer available; acknowledgment was not accepted".into(),
            ));
        };
        let expires_at: i64 = row.try_get("expires_at")?;
        if envelope_is_expired(expires_at, now_seconds()) {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "delivery acknowledgment arrived after envelope expiry".into(),
            ));
        }
        let current_status: String = row.try_get("delivery_status")?;
        let stored_hash: Option<Vec<u8>> = row.try_get("ciphertext_hash")?;
        let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
        let hash_matches =
            ack_ciphertext_hash_matches(stored_hash.as_deref(), &ciphertext, &supplied_hash);
        if !hash_matches {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "ciphertext hash does not match the accepted envelope".into(),
            ));
        }

        if current_status != "queued" {
            let same_receipt = current_status == outcome && hash_matches;
            if same_receipt {
                acknowledged = acknowledged.saturating_add(1);
                continue;
            }
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "delivery acknowledgment does not match the existing receipt".into(),
            ));
        }
        let result = sqlx::query(
            "UPDATE relay_envelopes SET delivery_status = ?, delivered_at = UNIX_TIMESTAMP(), ciphertext = ?, ciphertext_hash = COALESCE(ciphertext_hash, ?) WHERE envelope_id = ? AND recipient_wallet = ? AND recipient_device_id = ? AND delivery_status = 'queued' AND expires_at > UNIX_TIMESTAMP()",
        )
        .bind(&outcome)
        .bind(Vec::<u8>::new())
        .bind(supplied_hash.to_vec())
        .bind(&envelope_id)
        .bind(&auth.wallet)
        .bind(&auth.device_id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(AppError::Conflict(
                "delivery acknowledgment changed concurrently".into(),
            ));
        }
        acknowledged = acknowledged.saturating_add(1);
    }
    transaction.commit().await?;
    Ok(Json(AckResponse { acknowledged }))
}

async fn read_delivery_status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<DeliveryStatusRequest>,
) -> Result<Json<DeliveryStatusResponse>, AppError> {
    state.limiter.check(
        rate_key(addr, "delivery-status"),
        120,
        Duration::from_secs(60),
    )?;
    let auth = authenticated_session(&headers, &state.pool).await?;
    if request.envelope_ids.is_empty() || request.envelope_ids.len() > 100 {
        return Err(AppError::BadRequest(
            "envelope_ids must contain 1 to 100 values".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut statuses = Vec::new();
    let now = now_seconds();
    for value in request.envelope_ids {
        let envelope_id = normalized_envelope_id(&value)?;
        if !seen.insert(envelope_id.clone()) {
            return Err(AppError::BadRequest(
                "envelope_ids must not contain duplicates".into(),
            ));
        }
        let row = sqlx::query(
            "SELECT e.delivery_status, e.delivered_at, e.expires_at, e.ciphertext_hash, d.presence_until FROM relay_envelopes e JOIN relay_devices d ON d.wallet_address = e.recipient_wallet AND d.device_id = e.recipient_device_id WHERE e.envelope_id = ? AND e.sender_wallet = ? AND e.sender_device_id = ?",
        )
        .bind(&envelope_id)
        .bind(&auth.wallet)
        .bind(&auth.device_id)
        .fetch_optional(&state.pool)
        .await?;
        if let Some(row) = row {
            let hash: Option<Vec<u8>> = row.try_get("ciphertext_hash")?;
            let presence_until: i64 = row.try_get("presence_until")?;
            statuses.push(DeliveryStatusRecord {
                envelope_id,
                status: row.try_get("delivery_status")?,
                delivered_at: row.try_get("delivered_at")?,
                expires_at: row.try_get("expires_at")?,
                ciphertext_hash: hash.map(|bytes| format!("0x{}", hex::encode(bytes))),
                recipient_online: presence_until > now,
            });
        }
    }
    Ok(Json(DeliveryStatusResponse { statuses }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_data_shape_matches_the_wallet_contract() {
        let hash = [0x22_u8; 32];
        let value = typed_data_json(
            "0x0000000000000000000000000000000000000001",
            "11111111-1111-4111-8111-111111111111",
            &hash,
            "nonce",
            42,
        );
        assert_eq!(value["primaryType"], "IdentityKeyBinding");
        assert_eq!(value["domain"]["name"], "NODO Secure Messaging");
        assert_eq!(value["domain"]["version"], "1");
        assert_eq!(value["domain"]["chainId"], 11155111_u64);
        assert_eq!(value["domain"]["chainId"].as_u64(), Some(11155111));
        assert_eq!(value["message"]["expiresAt"].as_u64(), Some(42));
        let fields = value["types"]["IdentityKeyBinding"].as_array().unwrap();
        let names = fields
            .iter()
            .map(|field| field["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "wallet",
                "deviceId",
                "identityKeyHash",
                "nonce",
                "expiresAt"
            ]
        );
        let types = fields
            .iter()
            .map(|field| field["type"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(types, ["address", "string", "bytes32", "string", "uint64"]);
    }

    #[test]
    fn envelope_expiry_is_inclusive_at_the_deadline() {
        assert!(!envelope_is_expired(1_000, 999));
        assert!(envelope_is_expired(1_000, 1_000));
        assert!(envelope_is_expired(1_000, 1_001));
    }

    #[test]
    fn envelope_ids_must_be_rfc4122_uuid_v4() {
        let mut valid_bytes = [0_u8; 16];
        valid_bytes[6] = 0x40;
        valid_bytes[8] = 0x80;
        let valid = Uuid::from_bytes(valid_bytes).to_string();
        assert_eq!(normalized_envelope_id(&valid).unwrap(), valid);
        assert!(normalized_envelope_id("00000000-0000-0000-0000-000000000000").is_err());

        let mut version_one_bytes = valid_bytes;
        version_one_bytes[6] = 0x10;
        assert!(normalized_envelope_id(&Uuid::from_bytes(version_one_bytes).to_string()).is_err());

        let mut invalid_variant_bytes = valid_bytes;
        invalid_variant_bytes[8] = 0x00;
        assert!(
            normalized_envelope_id(&Uuid::from_bytes(invalid_variant_bytes).to_string()).is_err()
        );
    }

    #[test]
    fn duplicate_envelope_is_idempotent_only_for_the_same_ciphertext() {
        let original = b"opaque ciphertext one";
        let original_hash = Keccak256::digest(original).to_vec();
        assert!(existing_ciphertext_matches(
            Some(&original_hash),
            original,
            &original_hash,
            original,
        ));

        let altered = b"opaque ciphertext two";
        let altered_hash = Keccak256::digest(altered).to_vec();
        assert!(!existing_ciphertext_matches(
            Some(&original_hash),
            original,
            &altered_hash,
            altered,
        ));
        assert!(existing_ciphertext_matches(
            None,
            original,
            &original_hash,
            original,
        ));
        assert!(!existing_ciphertext_matches(
            None,
            &[],
            &original_hash,
            original,
        ));
    }

    #[test]
    fn acknowledgment_hash_must_match_for_every_outcome() {
        let ciphertext = b"opaque relay ciphertext";
        let computed_hash = Keccak256::digest(ciphertext).to_vec();
        let mismatched_hash = vec![0x99_u8; 32];

        assert!(ack_ciphertext_hash_matches(
            Some(&computed_hash),
            ciphertext,
            &computed_hash,
        ));
        assert!(ack_ciphertext_hash_matches(
            None,
            ciphertext,
            &computed_hash,
        ));
        assert!(!ack_ciphertext_hash_matches(
            Some(&computed_hash),
            ciphertext,
            &mismatched_hash,
        ));
        assert!(!ack_ciphertext_hash_matches(None, &[], &computed_hash));
    }

    #[test]
    fn device_identity_and_one_time_prekey_signatures_are_verified() {
        use ring::{
            rand::SystemRandom,
            signature::{Ed25519KeyPair, KeyPair},
        };

        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let identity = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let identity_key = identity.public_key().as_ref();
        let curve_identity_key = [0x31_u8; 32];
        let one_time_key = [0x42_u8; 32];

        let mut device_message = DEVICE_IDENTITY_DOMAIN.to_vec();
        device_message.extend_from_slice(&curve_identity_key);
        let device_signature = identity.sign(&device_message);
        assert!(verify_ed25519_signature(
            identity_key,
            &device_message,
            device_signature.as_ref(),
            "signed_prekey.signature"
        )
        .is_ok());

        let mut bundle_message = BUNDLE_DOMAIN.to_vec();
        bundle_message.extend_from_slice(&curve_identity_key);
        bundle_message.extend_from_slice(&one_time_key);
        let bundle_signature = identity.sign(&bundle_message);
        assert!(verify_ed25519_signature(
            identity_key,
            &bundle_message,
            bundle_signature.as_ref(),
            "one_time_prekey.signature"
        )
        .is_ok());

        let mut altered_message = bundle_message;
        altered_message[0] ^= 1;
        assert!(verify_ed25519_signature(
            identity_key,
            &altered_message,
            bundle_signature.as_ref(),
            "one_time_prekey.signature"
        )
        .is_err());
    }
}
