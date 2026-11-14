use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export async function nodoRelayFetch(path, method, bodyJson, bearerToken) {
  if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//")) {
    throw new Error("Relay requests must use a same-origin relative path.");
  }
  const headers = { accept: "application/json" };
  const request = { method, headers, cache: "no-store", credentials: "same-origin" };
  if (bodyJson) {
    headers["content-type"] = "application/json";
    request.body = bodyJson;
  }
  if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;
  const response = await fetch(path, request);
  const text = await response.text();
  let value = null;
  if (text) {
    try { value = JSON.parse(text); }
    catch (_) { throw new Error(`Relay returned non-JSON data (HTTP ${response.status}).`); }
  }
  if (!response.ok) {
    const message = value?.message || value?.error || `Relay request failed (HTTP ${response.status}).`;
    throw new Error(`HTTP ${response.status}: ${String(message)}`);
  }
  return JSON.stringify(value);
}
"#)]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = nodoRelayFetch)]
    async fn js_nodo_relay_fetch(
        path: &str,
        method: &str,
        body_json: &str,
        bearer_token: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: wasm_bindgen::JsValue) -> String {
    error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(&error, &wasm_bindgen::JsValue::from_str("message"))
                .ok()
                .and_then(|message| message.as_string())
        })
        .unwrap_or_else(|| "The secure-message relay request failed.".to_string())
}

/// Issue a same-origin relay request and deserialize its JSON response.
/// The optional bearer token is supplied from transient unlocked UI state and
/// is never persisted by this module.
#[cfg(target_arch = "wasm32")]
pub async fn call<T: DeserializeOwned>(
    path: &str,
    method: &str,
    body: Option<Value>,
    bearer_token: Option<&str>,
) -> Result<T, String> {
    let body_json = body
        .map(|value| serde_json::to_string(&value))
        .transpose()
        .map_err(|error| format!("Could not encode relay request: {error}"))?
        .unwrap_or_default();
    let raw = js_nodo_relay_fetch(path, method, &body_json, bearer_token.unwrap_or_default())
        .await
        .map_err(js_error)?;
    serde_json::from_str(&raw).map_err(|error| format!("Invalid relay JSON response: {error}"))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn call<T: DeserializeOwned>(
    _path: &str,
    _method: &str,
    _body: Option<Value>,
    _bearer_token: Option<&str>,
) -> Result<T, String> {
    Err("The same-origin relay client is available in the web application.".to_string())
}

/// Convert vodozemac's standard unpadded base64 string to the relay's unpadded
/// URL-safe base64 representation.
pub fn standard_to_urlsafe(value: &str) -> Result<String, String> {
    let bytes = vodozemac::base64_decode(value)
        .map_err(|error| format!("Invalid protocol base64 value: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Convert the relay's unpadded URL-safe base64 string to vodozemac's standard
/// unpadded base64 representation.
pub fn urlsafe_to_standard(value: &str) -> Result<String, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("Invalid relay base64 value: {error}"))?;
    Ok(STANDARD_NO_PAD.encode(bytes))
}

pub fn encode_urlsafe(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_urlsafe(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("Invalid relay base64 value: {error}"))
}
