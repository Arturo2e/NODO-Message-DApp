#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
function openNodoSecureDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("nodo-secure-storage", 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("encrypted_states")) {
        db.createObjectStore("encrypted_states");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("IndexedDB could not be opened"));
    request.onblocked = () => reject(new Error("IndexedDB upgrade is blocked by another NODO tab"));
  });
}

function runNodoSecureTransaction(mode, operation) {
  return openNodoSecureDb().then(db => new Promise((resolve, reject) => {
    let settled = false;
    const tx = db.transaction("encrypted_states", mode);
    const store = tx.objectStore("encrypted_states");
    let request;
    try {
      request = operation(store);
    } catch (error) {
      db.close();
      reject(error);
      return;
    }
    request.onsuccess = () => {
      if (mode === "readonly" && !settled) {
        settled = true;
        resolve(request.result === undefined ? null : request.result);
      }
    };
    request.onerror = () => {
      if (!settled) {
        settled = true;
        reject(request.error || new Error("IndexedDB request failed"));
      }
    };
    tx.oncomplete = () => {
      db.close();
      if (!settled) {
        settled = true;
        resolve(true);
      }
    };
    tx.onabort = tx.onerror = () => {
      db.close();
      if (!settled) {
        settled = true;
        reject(tx.error || new Error("IndexedDB transaction failed"));
      }
    };
  }));
}

const nodoProfileLockReleases = new Map();

export function acquireNodoSecureProfileLock(walletAddress) {
  const locks = globalThis.navigator?.locks;
  if (!locks || typeof locks.request !== "function") {
    return Promise.reject(new Error("Este navegador no ofrece Web Locks; el perfil se mantuvo bloqueado para evitar corrupción del ratchet entre pestañas."));
  }
  const key = `nodo-secure-profile:${String(walletAddress).toLowerCase()}`;
  if (nodoProfileLockReleases.has(key)) return Promise.resolve(false);

  let releaseGate;
  const releasePromise = new Promise(resolve => { releaseGate = resolve; });
  return new Promise((resolve, reject) => {
    let settled = false;
    locks.request(key, { mode: "exclusive", ifAvailable: true }, async lock => {
      if (!lock) {
        settled = true;
        resolve(false);
        return;
      }
      nodoProfileLockReleases.set(key, releaseGate);
      settled = true;
      resolve(true);
      await releasePromise;
    }).catch(error => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
  });
}

export function releaseNodoSecureProfileLock(walletAddress) {
  const key = `nodo-secure-profile:${String(walletAddress).toLowerCase()}`;
  const release = nodoProfileLockReleases.get(key);
  if (release) {
    nodoProfileLockReleases.delete(key);
    release();
  }
}

export function loadEncryptedCryptoState(walletAddress) {
  return runNodoSecureTransaction("readonly", store => store.get(walletAddress.toLowerCase()));
}

export function saveEncryptedCryptoState(walletAddress, encryptedBlob) {
  return runNodoSecureTransaction("readwrite", store => store.put(encryptedBlob, walletAddress.toLowerCase()));
}

"#)]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = acquireNodoSecureProfileLock)]
    fn js_acquire_nodo_secure_profile_lock(
        wallet_address: &str,
    ) -> Result<js_sys::Promise, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = releaseNodoSecureProfileLock)]
    fn js_release_nodo_secure_profile_lock(
        wallet_address: &str,
    ) -> Result<(), wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = loadEncryptedCryptoState)]
    fn js_load_encrypted_crypto_state(
        wallet_address: &str,
    ) -> Result<js_sys::Promise, wasm_bindgen::JsValue>;

    #[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = saveEncryptedCryptoState)]
    fn js_save_encrypted_crypto_state(
        wallet_address: &str,
        encrypted_blob: &str,
    ) -> Result<js_sys::Promise, wasm_bindgen::JsValue>;
}

pub struct WalletProfileLock {
    #[cfg(target_arch = "wasm32")]
    wallet_address: String,
}

impl Drop for WalletProfileLock {
    fn drop(&mut self) {
        #[cfg(target_arch = "wasm32")]
        if !self.wallet_address.is_empty() {
            let _ = js_release_nodo_secure_profile_lock(&self.wallet_address);
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn js_error(value: wasm_bindgen::JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(&value, &wasm_bindgen::JsValue::from_str("message"))
                .ok()
                .and_then(|message| message.as_string())
        })
        .unwrap_or_else(|| "No se pudo acceder al almacenamiento seguro del navegador.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn acquire_wallet_profile_lock(
    wallet_address: &str,
) -> Result<WalletProfileLock, String> {
    let promise = js_acquire_nodo_secure_profile_lock(wallet_address).map_err(js_error)?;
    let result = wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(js_error)?;
    if !result.as_bool().unwrap_or(false) {
        return Err("Este perfil ya está abierto en otra pestaña. Bloquéalo allí o cierra esa pestaña antes de desbloquearlo aquí.".to_string());
    }
    Ok(WalletProfileLock {
        wallet_address: wallet_address.to_ascii_lowercase(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn acquire_wallet_profile_lock(
    _wallet_address: &str,
) -> Result<WalletProfileLock, String> {
    Ok(WalletProfileLock {})
}

#[cfg(target_arch = "wasm32")]
pub async fn load_encrypted_state(wallet_address: &str) -> Result<Option<String>, String> {
    let promise = js_load_encrypted_crypto_state(wallet_address).map_err(js_error)?;
    let result = wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(js_error)?;
    if result.is_null() || result.is_undefined() {
        Ok(None)
    } else {
        result
            .as_string()
            .map(Some)
            .ok_or_else(|| "El almacenamiento seguro devolvió un estado inválido.".to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn load_encrypted_state(_wallet_address: &str) -> Result<Option<String>, String> {
    Err("El almacenamiento de claves está disponible en la aplicación web.".to_string())
}

#[cfg(target_arch = "wasm32")]
pub async fn save_encrypted_state(
    wallet_address: &str,
    encrypted_blob: &str,
) -> Result<(), String> {
    let promise =
        js_save_encrypted_crypto_state(wallet_address, encrypted_blob).map_err(js_error)?;
    wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map(|_| ())
        .map_err(js_error)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn save_encrypted_state(
    _wallet_address: &str,
    _encrypted_blob: &str,
) -> Result<(), String> {
    Err("El almacenamiento de claves está disponible en la aplicación web.".to_string())
}
