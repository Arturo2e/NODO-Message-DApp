use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletSnapshot {
    pub account: Option<String>,
    pub chain_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainMessage {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub content_hash: String,
    pub created_at: String,
    pub amount: String,
    pub is_read: bool,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityKeyBinding {
    pub wallet: String,
    pub device_id: String,
    pub identity_key_hash: String,
    pub nonce: String,
    pub expires_at: u64,
}

/// Returns true for a syntactically valid 20-byte EVM address.
///
/// This deliberately does not enforce a checksum: MetaMask and the provider
/// accept checksum or all-lower/all-upper hexadecimal forms.
pub fn is_evm_address(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 42
        && bytes[0..2] == *b"0x"
        && bytes[2..].iter().all(|byte| byte.is_ascii_hexdigit())
}

pub fn is_sepolia_chain_id(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("0xaa36a7") || value.trim() == "11155111"
}

/// Normalizes an exact decimal ETH amount without using a floating point value.
/// At most 18 fractional decimal places are accepted and zero is rejected.
pub fn normalize_native_amount(value: &str) -> Result<String, String> {
    let value = value.trim();
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (value.contains('.') && fraction.is_empty())
        || fraction.len() > 18
    {
        return Err("El importe debe ser un decimal exacto positivo con hasta 18 decimales (sin exponentes).".to_string());
    }

    let canonical_whole = whole.trim_start_matches('0');
    let canonical_whole = if canonical_whole.is_empty() {
        "0"
    } else {
        canonical_whole
    };
    let canonical_fraction = fraction.trim_end_matches('0');
    if canonical_whole == "0" && canonical_fraction.is_empty() {
        return Err("El importe debe ser mayor que cero.".to_string());
    }
    if canonical_fraction.is_empty() {
        Ok(canonical_whole.to_string())
    } else {
        Ok(format!("{canonical_whole}.{canonical_fraction}"))
    }
}

pub fn validate_native_transfer(
    recipient: &str,
    amount: &str,
    wallet: Option<&str>,
    chain_id: &str,
) -> Result<String, String> {
    if !is_evm_address(recipient) {
        return Err("La dirección destinataria no es una dirección EVM válida.".to_string());
    }
    let normalized_amount = normalize_native_amount(amount)?;
    let wallet = wallet.ok_or_else(|| "Conecta una wallet antes de transferir ETH.".to_string())?;
    if !is_evm_address(wallet) {
        return Err("La cuenta activa no es una dirección EVM válida.".to_string());
    }
    if !is_sepolia_chain_id(chain_id) {
        return Err(
            "Selecciona Ethereum Sepolia (chainId 11155111) antes de transferir.".to_string(),
        );
    }
    Ok(normalized_amount)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
let evmClient;
let provider;
let eventProvider;
let eventRefresh;
let eventDisconnect;
let eventSequence = 0;
const sepoliaRpc = "https://ethereum-sepolia-rpc.publicnode.com";
const networkMap = { "0xaa36a7": sepoliaRpc };
const BOARD_ABI = [
  { type: "function", name: "sendMessage", stateMutability: "payable", inputs: [{ name: "recipient", type: "address" }, { name: "contentHash", type: "bytes32" }], outputs: [{ name: "messageId", type: "uint256" }] },
  { type: "function", name: "getInboxIds", stateMutability: "view", inputs: [{ name: "account", type: "address" }], outputs: [{ name: "ids", type: "uint256[]" }] },
  { type: "function", name: "getSentIds", stateMutability: "view", inputs: [{ name: "account", type: "address" }], outputs: [{ name: "ids", type: "uint256[]" }] },
  { type: "function", name: "getMessage", stateMutability: "view", inputs: [{ name: "id", type: "uint256" }], outputs: [{ name: "sender", type: "address" }, { name: "recipient", type: "address" }, { name: "contentHash", type: "bytes32" }, { name: "createdAt", type: "uint64" }, { name: "amount", type: "uint256" }, { name: "isRead", type: "bool" }, { name: "cancelled", type: "bool" }] }
];

async function ensureClient() {
  if (evmClient) return evmClient;
  const { createEVMClient } = await import("https://esm.sh/@metamask/connect-evm@2.1.1");
  evmClient = await createEVMClient({
    dapp: { name: "NODO", url: window.location.origin },
    api: { supportedNetworks: networkMap }
  });
  return evmClient;
}

function injectedMetaMaskProvider() {
  const injected = window.ethereum;
  const candidates = Array.isArray(injected?.providers) ? injected.providers : [injected];
  return candidates.find(candidate => candidate?.isMetaMask && typeof candidate.request === "function") || null;
}

async function activeProvider() {
  const injected = injectedMetaMaskProvider();
  if (injected) provider = injected;
  if (!provider || typeof provider.request !== "function") provider = (await ensureClient()).getProvider();
  attachProviderEvents();
  return provider;
}

function broadcastWallet(account, chainId) {
  window.dispatchEvent(new CustomEvent("nodo:wallet", {
    detail: JSON.stringify({ account: account || null, chainId: chainId || "" })
  }));
}

function attachProviderEvents() {
  if (!provider || eventProvider === provider || typeof provider.on !== "function") return;
  if (eventProvider && typeof eventProvider.removeListener === "function") {
    if (eventRefresh) eventProvider.removeListener("accountsChanged", eventRefresh);
    if (eventRefresh) eventProvider.removeListener("chainChanged", eventRefresh);
    if (eventDisconnect) eventProvider.removeListener("disconnect", eventDisconnect);
  }
  const watchedProvider = provider;
  eventProvider = watchedProvider;
  const refresh = async () => {
    const sequence = ++eventSequence;
    try {
      const accounts = await watchedProvider.request({ method: "eth_accounts", params: [] });
      const chainId = await watchedProvider.request({ method: "eth_chainId", params: [] });
      if (sequence !== eventSequence) return;
      broadcastWallet(accounts?.[0] || null, chainId || "");
    } catch (_) {
      if (sequence === eventSequence) broadcastWallet(null, "");
    }
  };
  const disconnect = () => {
    eventSequence += 1;
    broadcastWallet(null, "");
  };
  eventRefresh = refresh;
  eventDisconnect = disconnect;
  watchedProvider.on("accountsChanged", refresh);
  watchedProvider.on("chainChanged", refresh);
  watchedProvider.on("disconnect", disconnect);
}

export async function connectWallet() {
  const injected = injectedMetaMaskProvider();
  let accounts;
  let chainId;
  if (injected) {
    provider = injected;
    accounts = await provider.request({ method: "eth_requestAccounts", params: [] });
    chainId = await provider.request({ method: "eth_chainId", params: [] });
  } else {
    const client = await ensureClient();
    provider = client.getProvider();
    const result = await client.connect({ chainIds: ["0xaa36a7"] });
    accounts = result.accounts || await provider.request({ method: "eth_accounts", params: [] });
    chainId = result.chainId || await provider.request({ method: "eth_chainId", params: [] });
  }
  attachProviderEvents();
  const snapshot = { account: accounts?.[0] || null, chainId: String(chainId || "") };
  broadcastWallet(snapshot.account, snapshot.chainId);
  return JSON.stringify(snapshot);
}

export async function switchToSepolia() {
  provider = await activeProvider();
  try {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0xaa36a7" }] });
  } catch (error) {
    if (error?.code !== 4902) throw error;
    await provider.request({
      method: "wallet_addEthereumChain",
      params: [{ chainId: "0xaa36a7", chainName: "Sepolia", nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 }, rpcUrls: [sepoliaRpc], blockExplorerUrls: ["https://sepolia.etherscan.io"] }]
    });
  }
  const accounts = await provider.request({ method: "eth_accounts", params: [] });
  const chainId = await provider.request({ method: "eth_chainId", params: [] });
  const snapshot = { account: accounts?.[0] || null, chainId: String(chainId || "") };
  broadcastWallet(snapshot.account, snapshot.chainId);
  return JSON.stringify(snapshot);
}

async function requireDeployedContract(active, contractAddress) {
  const code = await active.request({ method: "eth_getCode", params: [contractAddress, "latest"] });
  if (typeof code !== "string" || /^0x0*$/i.test(code)) {
    throw new Error("No hay bytecode de contrato en esa dirección de Sepolia. Usa la dirección del MessageBoard desplegado, no la de una wallet ni una URL RPC.");
  }
}

async function readMessageBoardIds(reader, contractAddress, account) {
  try {
    const [incomingIds, outgoingIds] = await Promise.all([
      reader.readContract({ address: contractAddress, abi: BOARD_ABI, functionName: "getInboxIds", args: [account] }),
      reader.readContract({ address: contractAddress, abi: BOARD_ABI, functionName: "getSentIds", args: [account] })
    ]);
    if (!Array.isArray(incomingIds) || !Array.isArray(outgoingIds)) throw new Error("Las funciones de historial no devolvieron listas.");
    return { incomingIds, outgoingIds };
  } catch (error) {
    const detail = error?.shortMessage || error?.message || String(error);
    throw new Error(`No se pudo verificar la interfaz MessageBoard en esa dirección. Comprueba que sea el contrato correcto en Sepolia y que el RPC responda. Detalle: ${detail}`);
  }
}

export async function sendMessage(contractAddress, recipient, contentHash, amount, expectedAccount) {
  const active = await activeProvider();
  const expected = String(expectedAccount || "").toLowerCase();
  if (!expected) throw new Error("No se recibió la cuenta que inició el anclaje.");
  const assertCurrentWallet = async () => {
    const [chainId, accounts] = await Promise.all([
      active.request({ method: "eth_chainId", params: [] }),
      active.request({ method: "eth_accounts", params: [] })
    ]);
    if (String(chainId).toLowerCase() !== "0xaa36a7") throw new Error("Selecciona Ethereum Sepolia en MetaMask antes de escribir.");
    if (!accounts?.[0] || String(accounts[0]).toLowerCase() !== expected) throw new Error("La cuenta activa de MetaMask cambió. Vuelve a seleccionar el mensaje con la wallet correcta.");
    return accounts[0];
  };
  const account = await assertCurrentWallet();
  await requireDeployedContract(active, contractAddress);
  const [viem, chains] = await Promise.all([
    import("https://esm.sh/viem@2.57.7"),
    import("https://esm.sh/viem@2.57.7/chains")
  ]);
  const reader = viem.createPublicClient({ chain: chains.sepolia, transport: viem.custom(active) });
  await readMessageBoardIds(reader, contractAddress, account);
  await assertCurrentWallet();
  const wallet = viem.createWalletClient({ account, chain: chains.sepolia, transport: viem.custom(active) });
  const hash = await wallet.writeContract({
    address: contractAddress,
    abi: BOARD_ABI,
    functionName: "sendMessage",
    args: [recipient, contentHash],
    value: viem.parseEther(amount || "0")
  });
  return hash;
}

export async function waitForReceipt(transactionHash) {
  const active = await activeProvider();
  for (let index = 0; index < 60; index += 1) {
    const receipt = await active.request({ method: "eth_getTransactionReceipt", params: [transactionHash] });
    if (receipt) return receipt.status === "0x1" ? "confirmed" : "failed";
    await new Promise(resolve => setTimeout(resolve, 3000));
  }
  return "pending";
}

export async function loadInbox(contractAddress, account) {
  const active = await activeProvider();
  const chainId = await active.request({ method: "eth_chainId", params: [] });
  if (String(chainId).toLowerCase() !== "0xaa36a7") throw new Error("Conecta la wallet a Sepolia para leer este contrato.");
  await requireDeployedContract(active, contractAddress);
  const [viem, chains] = await Promise.all([
    import("https://esm.sh/viem@2.57.7"),
    import("https://esm.sh/viem@2.57.7/chains")
  ]);
  const reader = viem.createPublicClient({ chain: chains.sepolia, transport: viem.custom(active) });
  const { incomingIds, outgoingIds } = await readMessageBoardIds(reader, contractAddress, account);
  const recentIds = [...new Set([...incomingIds, ...outgoingIds].map(id => id.toString()))]
    .sort((left, right) => BigInt(left) > BigInt(right) ? -1 : BigInt(left) < BigInt(right) ? 1 : 0)
    .slice(0, 30);
  const records = [];
  for (const id of recentIds) {
    const result = await reader.readContract({ address: contractAddress, abi: BOARD_ABI, functionName: "getMessage", args: [BigInt(id)] });
    const field = (name, index) => result?.[name] ?? result?.[index];
    records.push({
      id: id.toString(), sender: field("sender", 0), recipient: field("recipient", 1),
      contentHash: field("contentHash", 2), createdAt: field("createdAt", 3).toString(),
      amount: viem.formatEther(field("amount", 4)), isRead: Boolean(field("isRead", 5)), cancelled: Boolean(field("cancelled", 6))
    });
  }
  return JSON.stringify(records);
}

const EIP712_DOMAIN_TYPES = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" }
];
const IDENTITY_KEY_BINDING_TYPES = [
  { name: "wallet", type: "address" },
  { name: "deviceId", type: "string" },
  { name: "identityKeyHash", type: "bytes32" },
  { name: "nonce", type: "string" },
  { name: "expiresAt", type: "uint64" }
];
const IDENTITY_KEY_BINDING_DOMAIN = {
  name: "NODO Secure Messaging",
  version: "1",
  chainId: 11155111
};

function isSepoliaChain(chainId) {
  try {
    return BigInt(String(chainId)) === 11155111n;
  } catch (_) {
    return false;
  }
}

function nativeAddressIsValid(value) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

// Keep this parser integer-only. In particular, do not use Number, parseFloat,
// or a locale-dependent conversion for a value that will become wei.
function normalizeNativeAmount(amount) {
  const text = String(amount ?? "").trim();
  if (!/^\d+(?:\.\d{1,18})?$/.test(text)) {
    throw new Error("El importe debe ser un decimal exacto positivo con hasta 18 decimales (sin exponentes).");
  }
  const [wholePart, fractionPart = ""] = text.split(".");
  const whole = wholePart.replace(/^0+(?=\d)/, "") || "0";
  const fraction = fractionPart.replace(/0+$/, "");
  if (whole === "0" && fraction.length === 0) throw new Error("El importe debe ser mayor que cero.");
  return fraction ? `${whole}.${fraction}` : whole;
}

function nativeAmountWeiHex(amount) {
  const normalized = normalizeNativeAmount(amount);
  const [wholePart, fractionPart = ""] = normalized.split(".");
  const wholeWei = BigInt(wholePart) * 1000000000000000000n;
  const fractionWei = fractionPart.length ? BigInt(fractionPart.padEnd(18, "0")) : 0n;
  const wei = wholeWei + fractionWei;
  if (wei <= 0n) throw new Error("El importe debe ser mayor que cero.");
  return `0x${wei.toString(16)}`;
}

function nativeTransferStatus(receipt) {
  const status = String(receipt?.status || "").toLowerCase();
  if (status === "0x1" || status === "0x01") return "confirmed";
  if (status === "0x0" || status === "0x00") return "reverted";
  throw new Error("El receipt de Sepolia no contiene un estado de ejecución reconocible.");
}

function nativeTransferHashIsValid(transactionHash) {
  return typeof transactionHash === "string" && /^0x[0-9a-fA-F]{64}$/.test(transactionHash);
}

// Explicit user action only. This sends a native ETH transaction with no
// contract, calldata, message body, or automatic retry.
export async function sendNativeTransfer(recipient, amount, expectedAccount) {
  if (!nativeAddressIsValid(recipient)) throw new Error("La dirección destinataria no es una dirección EVM válida.");
  if (!nativeAddressIsValid(expectedAccount)) throw new Error("La cuenta activa no es una dirección EVM válida.");
  const normalizedAmount = normalizeNativeAmount(amount);
  const value = nativeAmountWeiHex(normalizedAmount);
  const active = await activeProvider();

  // These checks intentionally happen immediately before eth_sendTransaction.
  const [chainId, accounts] = await Promise.all([
    active.request({ method: "eth_chainId", params: [] }),
    active.request({ method: "eth_accounts", params: [] })
  ]);
  if (!isSepoliaChain(chainId)) throw new Error("Selecciona Ethereum Sepolia (chainId 11155111) antes de transferir.");
  const account = accounts?.[0];
  if (!account || String(account).toLowerCase() !== String(expectedAccount).toLowerCase()) {
    throw new Error("La cuenta activa de MetaMask cambió. Revisa la wallet antes de transferir.");
  }
  try {
    const hash = await active.request({
      method: "eth_sendTransaction",
      params: [{ from: account, to: recipient, value }]
    });
    if (!nativeTransferHashIsValid(hash)) throw new Error("MetaMask devolvió un hash de transacción inválido.");
    return hash;
  } catch (error) {
    const code = Number(error?.code ?? error?.data?.originalError?.code ?? error?.cause?.code);
    if (code === 4001) throw new Error("MetaMask rechazó la transferencia de ETH.");
    if (code === -32002) throw new Error("Ya hay una solicitud de transferencia pendiente en MetaMask.");
    throw error;
  }
}

export async function readNativeTransferReceipt(transactionHash) {
  if (!nativeTransferHashIsValid(transactionHash)) throw new Error("El hash de transacción no es válido.");
  const active = await activeProvider();
  const receipt = await active.request({ method: "eth_getTransactionReceipt", params: [transactionHash] });
  return receipt ? nativeTransferStatus(receipt) : "pending";
}

// Receipt reads are bounded and read-only. Reaching the limit leaves the
// submitted transaction pending; it never resubmits it.
export async function waitForNativeTransferReceipt(transactionHash) {
  if (!nativeTransferHashIsValid(transactionHash)) throw new Error("El hash de transacción no es válido.");
  const active = await activeProvider();
  for (let index = 0; index < 20; index += 1) {
    const receipt = await active.request({ method: "eth_getTransactionReceipt", params: [transactionHash] });
    if (receipt) return nativeTransferStatus(receipt);
    if (index < 19) await new Promise(resolve => setTimeout(resolve, 3000));
  }
  return "pending";
}

function normalizeIdentityKeyBinding(wallet, deviceId, identityKeyHash, nonce, expiresAt) {
  if (typeof wallet !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
    throw new Error("La wallet de la vinculación debe ser una dirección Ethereum válida.");
  }
  if (typeof deviceId !== "string") {
    throw new Error("El deviceId de la vinculación debe ser texto.");
  }
  if (typeof identityKeyHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(identityKeyHash)) {
    throw new Error("identityKeyHash debe ser un bytes32 hexadecimal (0x + 64 dígitos).");
  }
  if (typeof nonce !== "string") {
    throw new Error("El nonce de la vinculación debe ser texto.");
  }
  if (!(typeof expiresAt === "string" || typeof expiresAt === "number" || typeof expiresAt === "bigint")) {
    throw new Error("expiresAt debe ser un uint64.");
  }
  if (typeof expiresAt === "number" && (!Number.isSafeInteger(expiresAt) || expiresAt < 0)) {
    throw new Error("expiresAt debe ser un entero uint64 seguro; pásalo como texto si es grande.");
  }
  const expiresAtText = String(expiresAt);
  if (!/^\d+$/.test(expiresAtText) || BigInt(expiresAtText) > 18446744073709551615n) {
    throw new Error("expiresAt debe estar entre 0 y 2^64-1.");
  }
  return { wallet, deviceId, identityKeyHash, nonce, expiresAt: expiresAtText };
}

function identityKeyBindingRpcData(binding) {
  return {
    types: {
      EIP712Domain: EIP712_DOMAIN_TYPES,
      IdentityKeyBinding: IDENTITY_KEY_BINDING_TYPES
    },
    primaryType: "IdentityKeyBinding",
    domain: IDENTITY_KEY_BINDING_DOMAIN,
    message: binding
  };
}

function identityKeyBindingViemData(binding) {
  return {
    domain: IDENTITY_KEY_BINDING_DOMAIN,
    types: { IdentityKeyBinding: IDENTITY_KEY_BINDING_TYPES },
    primaryType: "IdentityKeyBinding",
    message: {
      wallet: binding.wallet,
      deviceId: binding.deviceId,
      identityKeyHash: binding.identityKeyHash,
      nonce: binding.nonce,
      expiresAt: BigInt(binding.expiresAt)
    }
  };
}

function signingError(error) {
  const code = Number(error?.code ?? error?.data?.originalError?.code ?? error?.cause?.code);
  const detail = String(error?.message || error || "").toLowerCase();
  if (code === 4001 || /user rejected|user denied|rejected the request/.test(detail)) {
    return new Error("MetaMask rechazó la firma EIP-712. La vinculación no fue aprobada.");
  }
  if (code === -32601 || /unsupported|not implemented|method not found/.test(detail)) {
    return new Error("El proveedor no admite el método eth_signTypedData_v4 requerido para esta vinculación.");
  }
  if (code === -32002) {
    return new Error("Ya hay una solicitud de MetaMask pendiente. Resuélvela antes de volver a firmar.");
  }
  return error instanceof Error ? error : new Error(String(error || "No se pudo completar la firma EIP-712."));
}

// Call this only from an explicit user action (for example, a “Vincular dispositivo” button).
// It asks the connected provider to sign and never reads, receives, or handles a private key.
export async function signIdentityKeyBinding(wallet, deviceId, identityKeyHash, nonce, expiresAt) {
  try {
    const binding = normalizeIdentityKeyBinding(wallet, deviceId, identityKeyHash, nonce, expiresAt);
    const active = await activeProvider();
    const chainId = await active.request({ method: "eth_chainId", params: [] });
    if (!isSepoliaChain(chainId)) {
      throw new Error("La firma de vinculación requiere Ethereum Sepolia (chainId 11155111).");
    }
    const accounts = await active.request({ method: "eth_accounts", params: [] });
    const connectedAccount = accounts?.[0];
    if (!connectedAccount) {
      throw new Error("No hay una cuenta conectada para firmar la vinculación.");
    }
    if (String(connectedAccount).toLowerCase() !== binding.wallet.toLowerCase()) {
      throw new Error("La wallet solicitada no coincide con la cuenta actualmente conectada en MetaMask.");
    }
    const signature = await active.request({
      method: "eth_signTypedData_v4",
      params: [connectedAccount, JSON.stringify(identityKeyBindingRpcData(binding))]
    });
    if (typeof signature !== "string" || !signature) {
      throw new Error("MetaMask devolvió una firma EIP-712 inválida.");
    }
    return signature;
  } catch (error) {
    throw signingError(error);
  }
}

export async function recoverIdentityKeyBindingSigner(wallet, deviceId, identityKeyHash, nonce, expiresAt, signature) {
  const binding = normalizeIdentityKeyBinding(wallet, deviceId, identityKeyHash, nonce, expiresAt);
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) {
    throw new Error("La firma recibida no es hexadecimal.");
  }
  const viem = await import("https://esm.sh/viem@2.57.7");
  return viem.recoverTypedDataAddress({
    ...identityKeyBindingViemData(binding),
    signature
  });
}

export async function verifyIdentityKeyBinding(wallet, deviceId, identityKeyHash, nonce, expiresAt, signature) {
  const binding = normalizeIdentityKeyBinding(wallet, deviceId, identityKeyHash, nonce, expiresAt);
  const signer = await recoverIdentityKeyBindingSigner(
    binding.wallet,
    binding.deviceId,
    binding.identityKeyHash,
    binding.nonce,
    binding.expiresAt,
    signature
  );
  return signer.toLowerCase() === binding.wallet.toLowerCase();
}
"#)]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = connectWallet)]
    pub fn js_connect_wallet() -> Result<js_sys::Promise, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = switchToSepolia)]
    pub async fn js_switch_to_sepolia() -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = sendMessage)]
    pub async fn js_send_message(
        contract: &str,
        recipient: &str,
        content_hash: &str,
        amount: &str,
        expected_account: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = sendNativeTransfer)]
    pub async fn js_send_native_transfer(
        recipient: &str,
        amount: &str,
        expected_account: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = readNativeTransferReceipt)]
    pub async fn js_read_native_transfer_receipt(
        transaction_hash: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = waitForNativeTransferReceipt)]
    pub async fn js_wait_for_native_transfer_receipt(
        transaction_hash: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = waitForReceipt)]
    pub async fn js_wait_for_receipt(
        transaction_hash: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = loadInbox)]
    pub async fn js_load_inbox(
        contract: &str,
        account: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = signIdentityKeyBinding)]
    pub async fn js_sign_identity_key_binding(
        wallet: &str,
        device_id: &str,
        identity_key_hash: &str,
        nonce: &str,
        expires_at: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = recoverIdentityKeyBindingSigner)]
    pub async fn js_recover_identity_key_binding_signer(
        wallet: &str,
        device_id: &str,
        identity_key_hash: &str,
        nonce: &str,
        expires_at: &str,
        signature: &str,
    ) -> Result<String, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = verifyIdentityKeyBinding)]
    pub async fn js_verify_identity_key_binding(
        wallet: &str,
        device_id: &str,
        identity_key_hash: &str,
        nonce: &str,
        expires_at: &str,
        signature: &str,
    ) -> Result<bool, wasm_bindgen::JsValue>;
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: wasm_bindgen::JsValue) -> String {
    let read_code = |name: &str| {
        js_sys::Reflect::get(&error, &wasm_bindgen::JsValue::from_str(name))
            .ok()
            .and_then(|value| value.as_f64())
            .map(|value| value as i64)
    };
    let code = read_code("code");
    let rpc_code = read_code("rpcCode");
    if code == Some(4001) || rpc_code == Some(4001) {
        return "MetaMask rechazó la conexión. Vuelve a intentarlo desde NODO y acepta la solicitud.".to_string();
    }
    if code == Some(-32002) || rpc_code == Some(-32002) {
        return "Ya hay una solicitud de MetaMask pendiente. Abre la extensión y resuélvela antes de volver a conectar.".to_string();
    }
    if code == Some(-32601) || rpc_code == Some(-32601) {
        return "El proveedor no admite el método solicitado por la wallet.".to_string();
    }
    let message = error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(&error, &wasm_bindgen::JsValue::from_str("message"))
                .ok()
                .and_then(|value| value.as_string())
        })
        .unwrap_or_else(|| "La operación de wallet no se completó.".to_string());
    if message
        .to_lowercase()
        .contains("transport request timed out")
    {
        return "MetaMask agotó el tiempo de conexión. Cierra cualquier solicitud pendiente, recarga NODO y pulsa «Conectar MetaMask» desde la página para aprobar el acceso.".to_string();
    }
    message
}

#[cfg(target_arch = "wasm32")]
pub fn connect() -> impl std::future::Future<Output = Result<WalletSnapshot, String>> {
    let promise = js_connect_wallet();
    async move {
        let promise = promise.map_err(js_error)?;
        let value = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(js_error)?;
        let value = value
            .as_string()
            .ok_or_else(|| "Respuesta de wallet inválida.".to_string())?;
        serde_json::from_str(&value)
            .map_err(|error| format!("Respuesta de wallet inválida: {error}"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn connect() -> Result<WalletSnapshot, String> {
    Err("La conexión de wallet está disponible en el sitio web.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn switch_to_sepolia() -> Result<WalletSnapshot, String> {
    let value = js_switch_to_sepolia().await.map_err(js_error)?;
    serde_json::from_str(&value).map_err(|error| format!("Respuesta de wallet inválida: {error}"))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn switch_to_sepolia() -> Result<WalletSnapshot, String> {
    Err("El cambio de red está disponible en el sitio web.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn send_message(
    contract: &str,
    recipient: &str,
    content_hash: &str,
    amount: &str,
    expected_account: &str,
) -> Result<String, String> {
    js_send_message(contract, recipient, content_hash, amount, expected_account)
        .await
        .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn send_message(
    _contract: &str,
    _recipient: &str,
    _content_hash: &str,
    _amount: &str,
    _expected_account: &str,
) -> Result<String, String> {
    Err("El envío on-chain está disponible en el sitio web.".to_string())
}

/// Requests one explicit native ETH transfer. The JavaScript bridge performs
/// the final account/chain checks immediately before `eth_sendTransaction`.
#[cfg(target_arch = "wasm32")]
pub async fn send_native_transfer(
    recipient: &str,
    amount: &str,
    expected_account: &str,
) -> Result<String, String> {
    let normalized =
        validate_native_transfer(recipient, amount, Some(expected_account), "0xaa36a7")?;
    js_send_native_transfer(recipient, &normalized, expected_account)
        .await
        .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn send_native_transfer(
    _recipient: &str,
    _amount: &str,
    _expected_account: &str,
) -> Result<String, String> {
    Err("La transferencia de ETH está disponible en el sitio web y requiere una acción explícita en MetaMask.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn read_native_transfer_receipt(transaction_hash: &str) -> Result<String, String> {
    js_read_native_transfer_receipt(transaction_hash)
        .await
        .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn read_native_transfer_receipt(_transaction_hash: &str) -> Result<String, String> {
    Err("La consulta de receipts está disponible en el sitio web.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn wait_for_native_transfer_receipt(transaction_hash: &str) -> Result<String, String> {
    js_wait_for_native_transfer_receipt(transaction_hash)
        .await
        .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn wait_for_native_transfer_receipt(_transaction_hash: &str) -> Result<String, String> {
    Err("La consulta de receipts está disponible en el sitio web.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn wait_for_receipt(transaction_hash: &str) -> Result<String, String> {
    js_wait_for_receipt(transaction_hash)
        .await
        .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn wait_for_receipt(_transaction_hash: &str) -> Result<String, String> {
    Err("La consulta de transacciones está disponible en el sitio web.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn load_inbox(contract: &str, account: &str) -> Result<Vec<ChainMessage>, String> {
    let value = js_load_inbox(contract, account).await.map_err(js_error)?;
    serde_json::from_str(&value).map_err(|error| format!("No se pudo leer el historial: {error}"))
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn load_inbox(_contract: &str, _account: &str) -> Result<Vec<ChainMessage>, String> {
    Err("La lectura del contrato está disponible en el sitio web.".to_string())
}

/// Signs an IdentityKeyBinding only when an explicit caller invokes this function.
/// The provider performs the signature; this bridge never accesses a private key.
#[cfg(target_arch = "wasm32")]
pub async fn sign_identity_key_binding(binding: &IdentityKeyBinding) -> Result<String, String> {
    let expires_at = binding.expires_at.to_string();
    js_sign_identity_key_binding(
        &binding.wallet,
        &binding.device_id,
        &binding.identity_key_hash,
        &binding.nonce,
        &expires_at,
    )
    .await
    .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sign_identity_key_binding(_binding: &IdentityKeyBinding) -> Result<String, String> {
    Err("La firma EIP-712 de wallet está disponible en el sitio web.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn recover_identity_key_binding_signer(
    binding: &IdentityKeyBinding,
    signature: &str,
) -> Result<String, String> {
    let expires_at = binding.expires_at.to_string();
    js_recover_identity_key_binding_signer(
        &binding.wallet,
        &binding.device_id,
        &binding.identity_key_hash,
        &binding.nonce,
        &expires_at,
        signature,
    )
    .await
    .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn recover_identity_key_binding_signer(
    _binding: &IdentityKeyBinding,
    _signature: &str,
) -> Result<String, String> {
    Err("La recuperación de firmas EIP-712 está disponible en el sitio web.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn verify_identity_key_binding(
    binding: &IdentityKeyBinding,
    signature: &str,
) -> Result<bool, String> {
    let expires_at = binding.expires_at.to_string();
    js_verify_identity_key_binding(
        &binding.wallet,
        &binding.device_id,
        &binding.identity_key_hash,
        &binding.nonce,
        &expires_at,
        signature,
    )
    .await
    .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn verify_identity_key_binding(
    _binding: &IdentityKeyBinding,
    _signature: &str,
) -> Result<bool, String> {
    Err("La verificación de firmas EIP-712 está disponible en el sitio web.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_decimal_amounts_are_normalized_without_float_rounding() {
        assert_eq!(normalize_native_amount("1"), Ok("1".to_string()));
        assert_eq!(normalize_native_amount("0001.2300"), Ok("1.23".to_string()));
        assert_eq!(
            normalize_native_amount("0.000000000000000001"),
            Ok("0.000000000000000001".to_string())
        );
        assert_eq!(
            normalize_native_amount("1.123456789012345678"),
            Ok("1.123456789012345678".to_string())
        );
    }

    #[test]
    fn zero_negative_exponent_and_over_precision_amounts_are_rejected() {
        for value in [
            "0",
            "0.0",
            "000.000",
            "-1",
            "+1",
            "1e-3",
            "1E3",
            "1.1234567890123456789",
            "1.",
            ".1",
        ] {
            assert!(normalize_native_amount(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn address_and_context_validation_rejects_invalid_address_wallet_or_chain() {
        let valid_recipient = "0x1111111111111111111111111111111111111111";
        let valid_wallet = "0x2222222222222222222222222222222222222222";
        assert!(is_evm_address(valid_recipient));
        assert!(!is_evm_address("0x111111111111111111111111111111111111111"));
        assert!(!is_evm_address(
            "0xgggggggggggggggggggggggggggggggggggggggg"
        ));
        assert!(!is_evm_address("1111111111111111111111111111111111111111"));
        assert!(
            validate_native_transfer(valid_recipient, "0.1", Some(valid_wallet), "0xaa36a7")
                .is_ok()
        );
        assert!(validate_native_transfer(
            "0xnot-an-address",
            "0.1",
            Some(valid_wallet),
            "0xaa36a7"
        )
        .is_err());
        assert!(validate_native_transfer(valid_recipient, "0.1", None, "0xaa36a7").is_err());
        assert!(
            validate_native_transfer(valid_recipient, "0.1", Some(valid_wallet), "0x1").is_err()
        );
    }
}
