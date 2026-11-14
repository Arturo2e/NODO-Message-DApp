use dioxus::prelude::*;
#[cfg(target_arch = "wasm32")]
use gloo_timers::future::TimeoutFuture;
use std::sync::atomic::Ordering;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    secure_messaging::{
        LocalChatMessage, OperationGeneration, OperationGuard, PeerDeviceInfo, PeerTrust,
        SecureMessagingSession,
    },
    wallet_bridge,
};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export function nodoUpdatePrivateHistoryScroll(peer) {
  requestAnimationFrame(() => {
    const node = document.querySelector('.secure-chat-message-list');
    if (!node) return;
    const changedPeer = node.dataset.peer !== peer;
    const oldHeight = Number(node.dataset.previousHeight || node.scrollHeight);
    const nearBottom = oldHeight - node.scrollTop - node.clientHeight < 48;
    if (changedPeer || nearBottom) node.scrollTop = node.scrollHeight;
    node.dataset.peer = peer;
    node.dataset.previousHeight = String(node.scrollHeight);
  });
}
"#)]
extern "C" {
    fn nodoUpdatePrivateHistoryScroll(peer: &str);
}

#[derive(Clone, PartialEq)]
struct ChatView {
    wallet: String,
    device_id: String,
    registered: bool,
    messages: Vec<LocalChatMessage>,
    pending_senders: Vec<String>,
}

impl Drop for ChatView {
    fn drop(&mut self) {
        for message in &mut self.messages {
            message.body.zeroize();
            message.sender_alias.zeroize();
        }
    }
}

fn restore_chat_session(
    mut session: Signal<Option<SecureMessagingSession>>,
    mut view: Signal<Option<ChatView>>,
    mut saved_peer_wallets: Signal<Vec<String>>,
    controller: SecureMessagingSession,
) {
    let next_view = ChatView {
        wallet: controller.wallet().to_string(),
        device_id: controller.device_id().to_string(),
        registered: controller.has_session(),
        messages: controller.messages_for_display(),
        pending_senders: controller.pending_senders.clone(),
    };
    if view.peek().as_ref() != Some(&next_view) {
        view.set(Some(next_view));
    }
    let peers = controller.conversation_wallets();
    if *saved_peer_wallets.peek() != peers {
        saved_peer_wallets.set(peers);
    }
    session.set(Some(controller));
}

#[component]
pub fn SecureChatPanel(
    wallet: Signal<Option<String>>,
    chain_id: Signal<String>,
    contacts: Vec<(String, String)>,
    contract_address: Signal<String>,
    network_epoch: Signal<u64>,
    language: Signal<String>,
    operation_generation: OperationGeneration,
    selected_peer: Signal<String>,
    saved_peer_wallets: Signal<Vec<String>>,
) -> Element {
    let english = language() == "en";
    let mut session = use_signal(|| None::<SecureMessagingSession>);
    let mut view = use_signal(|| None::<ChatView>);
    let mut password = use_signal(String::new);
    let mut alias = use_signal(String::new);
    let mut recipient = selected_peer;
    let mut draft = use_signal(String::new);
    let mut peer_devices = use_signal(Vec::<PeerDeviceInfo>::new);
    let mut selected_device = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut status_is_error = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut refreshing = use_signal(|| false);
    let mut wallet_epoch = use_signal(|| 0u64);
    let mut observed_wallet = use_signal(|| None::<String>);
    let mut observed_peer = use_signal(String::new);
    let mut saved_peer_wallets = saved_peer_wallets;

    let effect_generation = operation_generation.clone();
    use_effect(move || {
        let current_wallet = wallet().map(|value| value.to_ascii_lowercase());
        let previously_observed = observed_wallet();
        let session_wallet = session
            .read()
            .as_ref()
            .map(|active| active.wallet().to_ascii_lowercase());
        let session_wallet_changed = session_wallet
            .as_ref()
            .is_some_and(|active| Some(active) != current_wallet.as_ref());
        if previously_observed != current_wallet || session_wallet_changed {
            let previous_session = { session.write().take() };
            if let Some(mut previous_session) = previous_session {
                spawn(async move {
                    let _ = previous_session.mark_presence_offline().await;
                });
            }
            observed_wallet.set(current_wallet.clone());
            wallet_epoch.set(wallet_epoch().wrapping_add(1));
            effect_generation.fetch_add(1, Ordering::SeqCst);
            session.set(None);
            view.set(None);
            saved_peer_wallets.set(Vec::new());
            password.set(String::new());
            alias.set(String::new());
            recipient.set(String::new());
            draft.set(String::new());
            peer_devices.set(Vec::new());
            selected_device.set(String::new());
            busy.set(false);
            refreshing.set(false);
            status.set(
                "La wallet cambió o se desconectó. El perfil y el borrador privados quedaron bloqueados y borrados de la interfaz.".into(),
            );
            status_is_error.set(false);
        }
    });

    use_effect(move || {
        let next = recipient().trim().to_ascii_lowercase();
        if *observed_peer.peek() != next {
            observed_peer.set(next);
            peer_devices.set(Vec::new());
            selected_device.set(String::new());
            // Never carry another peer's draft into a newly selected conversation.
            draft.write().zeroize();
        }
    });

    let wallet_value = wallet();
    let wallet_address = wallet_value.clone().unwrap_or_default();
    let wallet_connected = wallet_value.is_some();
    let sepolia = chain_id().eq_ignore_ascii_case("0xaa36a7");
    let session_state = view.read();
    let active_wallet = session_state
        .as_ref()
        .map(|active| active.wallet.to_ascii_lowercase());
    let normalized_wallet = wallet_address.to_ascii_lowercase();
    let wallet_matches = active_wallet
        .as_deref()
        .is_some_and(|saved| saved == normalized_wallet);
    let unlocked = session_state.is_some() && wallet_matches;
    let registered = unlocked
        && session_state
            .as_ref()
            .is_some_and(|active| active.registered);
    let device_id = session_state
        .as_ref()
        .map(|active| active.device_id.clone())
        .unwrap_or_default();
    let local_messages = session_state
        .as_ref()
        .map(|active| messages_for_peer(&active.messages, recipient().trim()))
        .unwrap_or_default();
    let pending_senders = session_state
        .as_ref()
        .map(|active| active.pending_senders.clone())
        .unwrap_or_default();
    drop(session_state);

    let foreground_busy = busy() && !refreshing();

    #[cfg(target_arch = "wasm32")]
    use_effect(move || {
        let _ = view.read();
        let peer = recipient().trim().to_ascii_lowercase();
        nodoUpdatePrivateHistoryScroll(&peer);
    });

    #[cfg(target_arch = "wasm32")]
    {
        let language_for_loop = language.clone();
        let _presence_loop = use_future(move || {
            let heartbeat_language = language_for_loop.clone();
            let mut heartbeat_session = session;
            let mut heartbeat_busy = busy;
            let heartbeat_wallet = wallet;
            let heartbeat_epoch = wallet_epoch;
            let heartbeat_chain = chain_id;
            let mut heartbeat_status = status;
            let mut heartbeat_status_is_error = status_is_error;
            let heartbeat_recipient = recipient;
            let mut heartbeat_peer_devices = peer_devices;
            async move {
                loop {
                    TimeoutFuture::new(15_000).await;
                    if heartbeat_busy() {
                        continue;
                    }
                    let has_active_session = heartbeat_session
                        .read()
                        .as_ref()
                        .is_some_and(SecureMessagingSession::has_session);
                    let Some(mut controller) = heartbeat_session.write().take() else {
                        continue;
                    };
                    let expected_wallet = controller.wallet().to_string();
                    let operation_epoch = heartbeat_epoch();
                    if !operation_is_current(
                        heartbeat_wallet,
                        heartbeat_epoch,
                        operation_epoch,
                        &expected_wallet,
                    ) {
                        continue;
                    }
                    heartbeat_busy.set(true);
                    refreshing.set(true);
                    let cleanup_result = controller.prune_local_history().await;
                    if !operation_is_current(
                        heartbeat_wallet,
                        heartbeat_epoch,
                        operation_epoch,
                        &expected_wallet,
                    ) {
                        heartbeat_busy.set(false);
                        refreshing.set(false);
                        continue;
                    }
                    if let Err(error) = cleanup_result {
                        heartbeat_status.set(error);
                        heartbeat_status_is_error.set(true);
                    }
                    if !has_active_session || !heartbeat_chain().eq_ignore_ascii_case("0xaa36a7") {
                        restore_chat_session(
                            heartbeat_session,
                            view,
                            saved_peer_wallets,
                            controller,
                        );
                        heartbeat_busy.set(false);
                        refreshing.set(false);
                        continue;
                    }
                    let inbox_result = controller.refresh_inbox().await;
                    if !operation_is_current(
                        heartbeat_wallet,
                        heartbeat_epoch,
                        operation_epoch,
                        &expected_wallet,
                    ) {
                        heartbeat_busy.set(false);
                        refreshing.set(false);
                        continue;
                    }
                    let receipt_poll_failed = controller.refresh_delivery_statuses().await.is_err();
                    if !operation_is_current(
                        heartbeat_wallet,
                        heartbeat_epoch,
                        operation_epoch,
                        &expected_wallet,
                    ) {
                        heartbeat_busy.set(false);
                        refreshing.set(false);
                        continue;
                    }
                    let peer_wallet = heartbeat_recipient.read().trim().to_string();
                    if peer_wallet.len() == 42
                        && peer_wallet.starts_with("0x")
                        && !peer_wallet.eq_ignore_ascii_case(&expected_wallet)
                    {
                        let presence_result = controller.inspect_peer(&peer_wallet).await;
                        if !operation_is_current(
                            heartbeat_wallet,
                            heartbeat_epoch,
                            operation_epoch,
                            &expected_wallet,
                        ) {
                            heartbeat_busy.set(false);
                            refreshing.set(false);
                            continue;
                        }
                        if heartbeat_recipient()
                            .trim()
                            .eq_ignore_ascii_case(&peer_wallet)
                        {
                            match presence_result {
                                Ok(devices) => heartbeat_peer_devices.set(devices),
                                Err(_) => {
                                    let mut devices = heartbeat_peer_devices.read().clone();
                                    for device in &mut devices {
                                        device.online = None;
                                    }
                                    heartbeat_peer_devices.set(devices);
                                }
                            }
                        }
                    }
                    if let Ok(report) = inbox_result {
                        if report.metadata_capacity_full {
                            heartbeat_status.set(if heartbeat_language() == "en" {
                                "Local replay metadata is full. New encrypted envelopes remain pending at the relay until records expire; no new receipt was fabricated.".into()
                            } else {
                                "Los metadatos locales anti-replay están llenos. Los sobres nuevos permanecen pendientes en el relay hasta que caduquen los registros; no se inventó un recibo.".into()
                            });
                            heartbeat_status_is_error.set(true);
                        } else if report.delivered > 0 {
                            heartbeat_status.set(if heartbeat_language() == "en" {
                            format!("{} new message(s) decrypted, authenticated, and saved locally. The sender sees receipt only after the relay accepts the matching ciphertext hash.", report.delivered)
                        } else {
                            format!("{} mensaje(s) nuevo(s) descifrado(s), autenticado(s) y guardado(s) localmente. El remitente verá el recibo solo si el relay acepta el hash coincidente del ciphertext.", report.delivered)
                        });
                            heartbeat_status_is_error.set(false);
                        }
                    }
                    if receipt_poll_failed {
                        heartbeat_status.set(if heartbeat_language() == "en" {
                            "Could not refresh outgoing delivery receipts. Local messages remain saved; try a manual refresh.".into()
                        } else {
                            "No se pudieron actualizar los recibos de entrega salientes. Los mensajes locales siguen guardados; actualiza manualmente.".into()
                        });
                        heartbeat_status_is_error.set(true);
                    }
                    restore_chat_session(heartbeat_session, view, saved_peer_wallets, controller);
                    heartbeat_busy.set(false);
                    refreshing.set(false);
                }
            }
        });
    }

    let peer_devices_snapshot = peer_devices.read().clone();
    let contacts_snapshot = contacts.clone();
    let status_text = status();
    let status_class = if status_is_error() {
        "secure-chat-status error"
    } else {
        "secure-chat-status"
    };
    let can_anchor = wallet_connected
        && sepolia
        && contract_address().len() == 42
        && contract_address().starts_with("0x");

    let unlock_generation = operation_generation.clone();
    let unlock_click = move |_| {
        let Some(wallet_address) = wallet() else {
            status.set("Conecta MetaMask antes de abrir el perfil E2EE.".into());
            status_is_error.set(true);
            return;
        };
        let secret = password().clone();
        if secret.is_empty() {
            status.set("Escribe la contraseña local para cifrar o desbloquear el perfil.".into());
            status_is_error.set(true);
            return;
        }
        if !chain_id().eq_ignore_ascii_case("0xaa36a7") {
            status.set(
                "Cambia MetaMask a Ethereum Sepolia para vincular esta identidad de wallet.".into(),
            );
            status_is_error.set(true);
            return;
        }
        let session = session;
        let mut alias = alias;
        let mut password = password;
        let mut status = status;
        let mut status_is_error = status_is_error;
        let mut busy = busy;
        let wallet_signal = wallet;
        let epoch_signal = wallet_epoch;
        let operation_epoch = wallet_epoch();
        let expected_generation = unlock_generation.load(Ordering::SeqCst);
        let operation_guard = OperationGuard::new(unlock_generation.clone(), expected_generation);
        let expected_wallet = wallet_address.clone();
        spawn(async move {
            busy.set(true);
            match SecureMessagingSession::unlock(&wallet_address, secret, operation_guard).await {
                Ok((controller, existed)) => {
                    if !operation_is_current(
                        wallet_signal,
                        epoch_signal,
                        operation_epoch,
                        &expected_wallet,
                    ) {
                        drop(controller);
                        return;
                    }
                    alias.set(controller.self_alias().to_string());
                    restore_chat_session(session, view, saved_peer_wallets, controller);
                    password.set(String::new());
                    status.set(if existed {
                        "Perfil local desbloqueado. La contraseña no se envía al relay.".into()
                    } else {
                        "Perfil E2EE creado y cifrado en IndexedDB. Firma EIP-712 para publicarlo en el relay.".into()
                    });
                    status_is_error.set(false);
                }
                Err(error) => {
                    if !operation_is_current(
                        wallet_signal,
                        epoch_signal,
                        operation_epoch,
                        &expected_wallet,
                    ) {
                        return;
                    }
                    password.set(String::new());
                    status.set(error);
                    status_is_error.set(true);
                }
            }
            if operation_is_current(
                wallet_signal,
                epoch_signal,
                operation_epoch,
                &expected_wallet,
            ) {
                busy.set(false);
            }
        });
    };

    let register_click = move |_| {
        let controller = { session.write().take() };
        let Some(mut controller) = controller else {
            status.set("Desbloquea primero el perfil E2EE.".into());
            status_is_error.set(true);
            return;
        };
        let expected_wallet = controller.wallet().to_string();
        let operation_epoch = wallet_epoch();
        if !operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet) {
            return;
        }
        let wallet_signal = wallet;
        let epoch_signal = wallet_epoch;
        let session = session;
        let mut status = status;
        let mut status_is_error = status_is_error;
        let mut busy = busy;
        spawn(async move {
            busy.set(true);
            let result = controller.authenticate_and_register().await;
            if !operation_is_current(
                wallet_signal,
                epoch_signal,
                operation_epoch,
                &expected_wallet,
            ) {
                return;
            }
            let presence_active = if result.is_ok() {
                controller.renew_presence().await.is_ok()
            } else {
                false
            };
            if !operation_is_current(
                wallet_signal,
                epoch_signal,
                operation_epoch,
                &expected_wallet,
            ) {
                return;
            }
            match result {
                Ok(()) => {
                    status.set(if presence_active {
                        "Identidad vinculada por 365 días y bundles públicos registrados. La firma no consume gas; la sesión del relay dura 12 horas y el lease de presencia está activo.".into()
                    } else {
                        "Identidad vinculada y bundles públicos registrados. El relay no confirmó presencia todavía; NODO volverá a intentarlo automáticamente.".into()
                    });
                    status_is_error.set(!presence_active);
                }
                Err(error) => {
                    status.set(error);
                    status_is_error.set(true);
                }
            }
            restore_chat_session(session, view, saved_peer_wallets, controller);
            busy.set(false);
        });
    };

    let inspect_click = move |_| {
        let address = recipient().trim().to_string();
        let controller = { session.write().take() };
        let Some(controller) = controller else {
            status.set(
                "Desbloquea el perfil y registra el dispositivo antes de verificar contactos."
                    .into(),
            );
            status_is_error.set(true);
            return;
        };
        let expected_wallet = controller.wallet().to_string();
        let operation_epoch = wallet_epoch();
        if !operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet) {
            return;
        }
        if address.len() != 42 || !address.starts_with("0x") {
            restore_chat_session(session, view, saved_peer_wallets, controller);
            status.set("Escribe una wallet EVM válida para inspeccionar su identidad.".into());
            status_is_error.set(true);
            return;
        }
        let wallet_signal = wallet;
        let epoch_signal = wallet_epoch;
        let session = session;
        let mut peer_devices = peer_devices;
        let mut selected_device = selected_device;
        let mut status = status;
        let mut status_is_error = status_is_error;
        let mut busy = busy;
        spawn(async move {
            busy.set(true);
            let result = controller.inspect_peer(&address).await;
            if !operation_is_current(
                wallet_signal,
                epoch_signal,
                operation_epoch,
                &expected_wallet,
            ) {
                return;
            }
            if !recipient().trim().eq_ignore_ascii_case(&address) {
                restore_chat_session(session, view, saved_peer_wallets, controller);
                busy.set(false);
                return;
            }
            match result {
                Ok(devices) if devices.is_empty() => {
                    peer_devices.set(Vec::new());
                    selected_device.set(String::new());
                    status.set("No hay dispositivo publicado para esa wallet. La otra persona debe crear su perfil, conectar Sepolia y registrar su dispositivo.".into());
                    status_is_error.set(true);
                }
                Ok(devices) => {
                    let first_device = devices
                        .first()
                        .map(|device| device.device_id.clone())
                        .unwrap_or_default();
                    peer_devices.set(devices);
                    selected_device.set(first_device);
                    status.set("Bundle verificado criptográficamente. Compara la huella por otro canal antes de marcarla como verificada.".into());
                    status_is_error.set(false);
                }
                Err(error) => {
                    peer_devices.set(Vec::new());
                    selected_device.set(String::new());
                    status.set(error);
                    status_is_error.set(true);
                }
            }
            restore_chat_session(session, view, saved_peer_wallets, controller);
            busy.set(false);
        });
    };

    let send_click = move |_| {
        let to = recipient().trim().to_string();
        let device_id = selected_device();
        let body = Zeroizing::new(draft().trim().to_string());
        let controller = { session.write().take() };
        let Some(mut controller) = controller else {
            status.set("Desbloquea y registra el perfil E2EE antes de enviar.".into());
            status_is_error.set(true);
            return;
        };
        let expected_wallet = controller.wallet().to_string();
        let operation_epoch = wallet_epoch();
        if !operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet) {
            return;
        }
        let wallet_signal = wallet;
        let epoch_signal = wallet_epoch;
        let session = session;
        let mut status = status;
        let mut status_is_error = status_is_error;
        let mut draft = draft;
        let mut busy = busy;
        spawn(async move {
            busy.set(true);
            let result = controller
                .send_message(&to, &device_id, body.as_str())
                .await;
            if !operation_is_current(
                wallet_signal,
                epoch_signal,
                operation_epoch,
                &expected_wallet,
            ) {
                return;
            }
            match result {
                Ok(outcome) => {
                    if should_clear_draft_after_send(&outcome.status)
                        && draft.read().trim() == body.as_str()
                        && recipient().trim().eq_ignore_ascii_case(&to)
                        && selected_device() == device_id
                    {
                        draft.set(String::new());
                    }
                    status_is_error.set(send_outcome_is_error(&outcome.status));
                    status.set(send_outcome_message(
                        &outcome.status,
                        outcome.warning,
                        english,
                    ));
                }
                Err(error) => {
                    status.set(error);
                    status_is_error.set(true);
                }
            }
            restore_chat_session(session, view, saved_peer_wallets, controller);
            busy.set(false);
        });
    };

    let refresh_click = move |_| {
        let controller = { session.write().take() };
        let Some(mut controller) = controller else {
            status.set(
                "Desbloquea el perfil y registra el dispositivo para consultar la bandeja.".into(),
            );
            status_is_error.set(true);
            return;
        };
        let expected_wallet = controller.wallet().to_string();
        let operation_epoch = wallet_epoch();
        if !operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet) {
            return;
        }
        let wallet_signal = wallet;
        let epoch_signal = wallet_epoch;
        let session = session;
        let mut status = status;
        let mut status_is_error = status_is_error;
        let mut busy = busy;
        spawn(async move {
            busy.set(true);
            let result = controller.refresh_inbox().await;
            if !operation_is_current(
                wallet_signal,
                epoch_signal,
                operation_epoch,
                &expected_wallet,
            ) {
                return;
            }
            match result {
                Ok(report) => {
                    let summary = if english {
                        format!(
                            "E2EE inbox: {} message(s) decrypted, authenticated, and saved locally; {} sender(s) awaiting verification, {} unverified ciphertext(s) discarded, {} malformed envelope(s), {} authentication failure(s).",
                            report.delivered,
                            report.pending_senders.len(),
                            report.discarded_unverified,
                            report.malformed,
                            report.authentication_failed,
                        )
                    } else {
                        format!(
                            "Bandeja E2EE: {} mensaje(s) descifrado(s), autenticado(s) y guardado(s) localmente; {} remitente(s) por verificar, {} ciphertext no verificado(s) descartado(s), {} sobre(s) malformado(s), {} fallo(s) de autenticación.",
                            report.delivered,
                            report.pending_senders.len(),
                            report.discarded_unverified,
                            report.malformed,
                            report.authentication_failed,
                        )
                    };
                    let ack_not_confirmed = report.acknowledged < report.delivered;
                    let summary = if ack_not_confirmed {
                        if english {
                            format!("{summary} Not all delivery ACK items were confirmed; refresh again to retry.")
                        } else {
                            format!("{summary} No se confirmaron todos los ACK de entrega; actualiza otra vez para reintentar.")
                        }
                    } else {
                        summary
                    };
                    status.set(if report.more_pending {
                        if english {
                            format!("{summary} Refresh again to continue through the remaining queue.")
                        } else {
                            format!("{summary} Pulsa actualizar otra vez para continuar con el resto de la cola.")
                        }
                    } else if report.discarded_unverified > 0 {
                        if english {
                            format!("{summary} After confirming the fingerprint, ask the sender to resend those messages.")
                        } else {
                            format!("{summary} Después de confirmar la huella, pide al remitente que vuelva a enviar esos mensajes.")
                        }
                    } else if report.malformed > 0 || report.authentication_failed > 0 {
                        if english {
                            format!("{summary} Those envelopes were discarded without blocking the inbox.")
                        } else {
                            format!("{summary} Esos sobres se descartaron sin bloquear la bandeja.")
                        }
                    } else {
                        summary
                    });
                    if report.metadata_capacity_full {
                        let capacity_note = if english {
                            " New envelopes remain pending because the local replay-metadata store is full; they will be retried after records expire."
                        } else {
                            " Los sobres nuevos siguen pendientes porque el almacén local anti-replay está lleno; se consultarán de nuevo al caducar los registros."
                        };
                        status.write().push_str(capacity_note);
                    }
                    status_is_error.set(
                        report.rejected > 0 || ack_not_confirmed || report.metadata_capacity_full,
                    );
                    let receipt_poll_failed = controller.refresh_delivery_statuses().await.is_err();
                    if !operation_is_current(
                        wallet_signal,
                        epoch_signal,
                        operation_epoch,
                        &expected_wallet,
                    ) {
                        return;
                    }
                    if receipt_poll_failed {
                        status.set(if english {
                            "Could not refresh outgoing delivery receipts. Received messages remain saved locally; try refreshing again.".into()
                        } else {
                            "No se pudieron actualizar los recibos de entrega salientes. Los mensajes recibidos siguen guardados localmente; vuelve a actualizar.".into()
                        });
                        status_is_error.set(true);
                    }
                }
                Err(error) => {
                    status.set(error);
                    status_is_error.set(true);
                }
            }
            restore_chat_session(session, view, saved_peer_wallets, controller);
            busy.set(false);
        });
    };

    let save_alias_click = move |_| {
        let value = Zeroizing::new(alias().trim().to_string());
        let controller = { session.write().take() };
        let Some(mut controller) = controller else {
            status.set("Desbloquea el perfil antes de guardar tu alias.".into());
            status_is_error.set(true);
            return;
        };
        let expected_wallet = controller.wallet().to_string();
        let operation_epoch = wallet_epoch();
        if !operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet) {
            return;
        }
        let wallet_signal = wallet;
        let epoch_signal = wallet_epoch;
        let session = session;
        let mut status = status;
        let mut status_is_error = status_is_error;
        let mut busy = busy;
        spawn(async move {
            busy.set(true);
            let result = controller.set_self_alias(value.as_str()).await;
            if !operation_is_current(
                wallet_signal,
                epoch_signal,
                operation_epoch,
                &expected_wallet,
            ) {
                return;
            }
            match result {
                Ok(()) => {
                    status.set("Alias guardado en el perfil local cifrado; se compartirá solo dentro del mensaje cifrado.".into());
                    status_is_error.set(false);
                }
                Err(error) => {
                    status.set(error);
                    status_is_error.set(true);
                }
            }
            restore_chat_session(session, view, saved_peer_wallets, controller);
            busy.set(false);
        });
    };

    let lock_generation = operation_generation.clone();
    let mut lock_epoch = wallet_epoch;
    let lock_click = move |_| {
        let previous_session = { session.write().take() };
        if let Some(mut previous_session) = previous_session {
            spawn(async move {
                let _ = previous_session.mark_presence_offline().await;
            });
        }
        lock_generation.fetch_add(1, Ordering::SeqCst);
        lock_epoch.set(lock_epoch().wrapping_add(1));
        session.set(None);
        view.set(None);
        saved_peer_wallets.set(Vec::new());
        refreshing.set(false);
        password.set(String::new());
        alias.set(String::new());
        recipient.set(String::new());
        draft.set(String::new());
        peer_devices.set(Vec::new());
        selected_device.set(String::new());
        busy.set(false);
        status.set("Perfil bloqueado. Las claves privadas solo estarán disponibles al desbloquearlo otra vez.".into());
        status_is_error.set(false);
    };

    let unlock_label = if busy() {
        if english {
            "Opening profile…"
        } else {
            "Abriendo perfil…"
        }
    } else {
        if english {
            "Unlock / create encrypted profile"
        } else {
            "Abrir / crear perfil cifrado"
        }
    };
    let device_label = if english { "device" } else { "dispositivo" };

    rsx! {
        section { class: "secure-chat-section", id: "mensajeria-segura",
            div { class: "secure-chat-heading",
                div {
                    span { class: "section-kicker", if english { "PRIVATE CHAT · OLM TRIPLE-DH + DOUBLE RATCHET" } else { "CHAT PRIVADO · OLM TRIPLE-DH + DOUBLE RATCHET" } }
                    h2 { if english { "Your messages, readable. " } else { "Tus mensajes, legibles. " } span { class: "headline-accent", if english { "Your keys, local." } else { "Tus claves, locales." } } }
                    p { if english { "Open your local profile to read message text and Sent / Received UTC dates here. Text is encrypted in transit and only decrypted on your devices; an ACK confirms delivery, not that a person read it." } else { "Abre tu perfil local para leer aquí el texto y las fechas UTC de Enviado / Recibido. El texto viaja cifrado y solo se descifra en tus dispositivos; el ACK confirma entrega, no que una persona lo haya leído." } }
                }
                span { class: if registered && wallet_matches { "secure-chat-badge active" } else { "secure-chat-badge" }, if registered && wallet_matches { if english { "DEVICE REGISTERED" } else { "DISPOSITIVO REGISTRADO" } } else { if english { "KEYS IN THIS BROWSER" } else { "CLAVES EN EL NAVEGADOR" } } }
            }

            if !status_text.is_empty() {
                div { class: status_class, role: "status", "{localized_secure_status(&status_text, english)}" }
            }

            if !wallet_connected {
                div { class: "secure-chat-lock-card",
                    strong { if english { "Connect MetaMask to use an EVM identity." } else { "Conecta MetaMask para usar una identidad EVM." } }
                    p { if english { "NODO never receives your private key or seed phrase. A Sepolia EIP-712 signature binds only the device's public fingerprint." } else { "NODO nunca recibe la clave privada ni la frase semilla. La firma EIP-712 de Sepolia vincula solo la huella pública del dispositivo." } }
                }
            } else if !unlocked {
                div { class: "secure-chat-unlock",
                    div { class: "secure-chat-unlock-copy",
                        span { class: "section-kicker", if english { "ENCRYPTED LOCAL STORAGE · {short_wallet(&wallet_address)}" } else { "ALMACENAMIENTO LOCAL CIFRADO · {short_wallet(&wallet_address)}" } }
                        h3 { if english { "Unlock this device" } else { "Desbloquea tu dispositivo" } }
                        p { if english { "The profile lives in this browser's IndexedDB and is encrypted with a local password. It is not synced to the relay." } else { "El perfil vive en IndexedDB de este navegador y se cifra con una contraseña local. No se sincroniza al relay." } }
                    }
                    label { class: "field-label", if english { "LOCAL PASSWORD · NEVER SENT" } else { "CONTRASEÑA LOCAL · NUNCA SE ENVÍA" } }
                    input { class: "text-field secure-password", r#type: "password", autocomplete: "current-password", value: password(), oninput: move |event| password.set(event.value()), placeholder: if english { "12+ characters for a new profile" } else { "12+ caracteres para un perfil nuevo" }, aria_label: if english { "E2EE profile local password" } else { "Contraseña local del perfil E2EE" } }
                    button { class: "button button-primary", disabled: busy() || !sepolia, onclick: unlock_click, "{unlock_label}" }
                    if !sepolia { p { class: "secure-chat-warning", if english { "Switch your wallet to Ethereum Sepolia (chainId 11155111) before opening the profile." } else { "Cambia la wallet a Ethereum Sepolia (chainId 11155111) antes de abrir el perfil." } } }
                }
            } else {
                div { class: "secure-chat-toolbar",
                    div { class: "secure-chat-device-status",
                        span { class: "secure-chat-check", "✓" }
                        span { strong { if english { "Profile unlocked" } else { "Perfil desbloqueado" } } small { "Wallet {short_wallet(&wallet_address)} · {device_label} {short_device(&device_id)}" } }
                    }
                    div { class: "secure-chat-toolbar-actions",
                        span { class: "chat-refresh-indicator", role: "status", if refreshing() { if english { "Checking new messages…" } else { "Buscando mensajes nuevos…" } } }
                        if !registered { button { class: "button button-primary", disabled: busy() || !sepolia, onclick: register_click, if busy() { if english { "Waiting for MetaMask…" } else { "Esperando MetaMask…" } } else { if english { "Bind with EIP-712 signature" } else { "Vincular con firma EIP-712" } } } }
                        else { button { class: "button button-quiet", disabled: busy(), onclick: refresh_click, if busy() { if english { "Refreshing…" } else { "Actualizando…" } } else { if english { "Refresh inbox ↻" } else { "Actualizar bandeja ↻" } } } }
                        button { class: "button button-quiet", onclick: lock_click, if english { "Lock" } else { "Bloquear" } }
                    }
                }
                if !registered {
                    div { class: "secure-chat-warning", if english { "Cross-wallet delivery requires both people to register a device. Binding asks MetaMask for a typed signature, not a transaction or gas." } else { "La entrega entre wallets requiere que ambas registren su dispositivo. La vinculación solicita una firma tipada de MetaMask, no una transacción ni gas." } }
                }
                div {
                    div { class: "secure-chat-grid",
                        div { class: "secure-chat-card secure-chat-profile",
                            span { class: "section-kicker", if english { "YOUR IDENTITY ON THIS DEVICE" } else { "TU IDENTIDAD EN ESTE DISPOSITIVO" } }
                            label { class: "field-label", if english { "DISPLAY ALIAS · UP TO 48 CHARACTERS" } else { "ALIAS DE PRESENTACIÓN · HASTA 48 CARACTERES" } }
                            div { class: "secure-chat-input-row",
                                input { class: "text-field", r#type: "text", maxlength: "48", placeholder: if english { "For example, Alex" } else { "Por ejemplo, Alex" }, value: alias(), oninput: move |event| alias.set(event.value()), aria_label: if english { "Encrypted display alias" } else { "Alias cifrado de presentación" } }
                                button { class: "button button-quiet", disabled: busy(), onclick: save_alias_click, if english { "Save alias" } else { "Guardar alias" } }
                            }
                            p { class: "secure-chat-note", if english { "The alias is included inside the ciphertext; it is not published or sent as open metadata. It does not prove legal identity." } else { "El alias se incluye dentro del ciphertext; no se publica ni se envía como metadato abierto. No demuestra identidad civil." } }
                        }
                        div { class: "secure-chat-card secure-chat-recipient",
                            span { class: "section-kicker", if english { "INSPECT RECIPIENT WALLET" } else { "INSPECCIONAR WALLET DESTINATARIA" } }
                            if !contacts_snapshot.is_empty() {
                                label { class: "field-label", if english { "CONTACT SAVED IN THIS BROWSER" } else { "CONTACTO GUARDADO EN ESTE NAVEGADOR" } }
                                select { class: "text-field", value: recipient(), onchange: move |event| set_recipient_target(recipient, peer_devices, selected_device, event.value()), aria_label: if english { "Select a contact for encrypted messages" } else { "Seleccionar un contacto para mensajes cifrados" },
                                    option { value: "", if english { "Select a contact…" } else { "Selecciona un contacto…" } }
                                    for (name, address) in contacts_snapshot.clone() { option { value: "{address}", "{name} · {short_wallet(&address)}" } }
                                }
                            }
                            label { class: "field-label", if english { "RECIPIENT EVM WALLET" } else { "WALLET EVM DEL DESTINATARIO" } }
                            div { class: "secure-chat-input-row",
                                input { class: "text-field", r#type: "text", placeholder: "0x…", spellcheck: "false", autocomplete: "off", value: recipient(), oninput: move |event| set_recipient_target(recipient, peer_devices, selected_device, event.value()), aria_label: if english { "Recipient EVM wallet" } else { "Wallet EVM destinataria" } }
                                button { class: "button button-quiet", disabled: busy() || !registered, onclick: inspect_click, if foreground_busy { if english { "Verifying…" } else { "Verificando…" } } else { if english { "Verify" } else { "Verificar" } } }
                            }
                            p { class: "secure-chat-note", if english { "NODO validates the wallet signature and the bundle's Ed25519 signature. Confirm the fingerprint through another channel; a first key or key change is never trusted automatically." } else { "NODO valida la firma de la wallet y la firma Ed25519 del bundle. Confirma la huella por otro canal; una primera clave o un cambio nunca se confirman automáticamente." } }
                            p { class: "secure-chat-note", if english { "This version verifies EOA signatures with EIP-712 recovery; EIP-1271 contract wallets are unsupported and are never shown as verified." } else { "Esta versión verifica firmas EOA con recuperación EIP-712; las wallets de contrato EIP-1271 no son compatibles y nunca se muestran como verificadas." } }
                            if !peer_devices_snapshot.is_empty() {
                                div { class: "peer-device-list",
                                    for device in peer_devices_snapshot.clone() {
                                        div { class: "peer-device-card",
                                            div { class: "peer-device-topline",
                                                strong { if english { "Device {short_device(&device.device_id)}" } else { "Dispositivo {short_device(&device.device_id)}" } }
                                                span { class: trust_class(&device.trust), "{trust_label(&device.trust, english)}" }
                                            }
                                            code { class: "peer-fingerprint", "{device.fingerprint}" }
                                            p { class: "secure-chat-note", if english { "{device.available_prekeys} one-time prekeys available." } else { "{device.available_prekeys} prekeys de un solo uso disponibles." } }
                                            p { class: if device.online == Some(true) { "secure-chat-note presence-online" } else if device.online == Some(false) { "secure-chat-note presence-offline" } else { "secure-chat-note presence-unknown" },
                                                if english {
                                                    if device.online == Some(true) { "ONLINE · authenticated relay lease active" } else if device.online == Some(false) { "OFFLINE · encrypted envelopes will wait in the mailbox" } else { "PRESENCE UNKNOWN · verify this recipient again" }
                                                } else {
                                                    if device.online == Some(true) { "EN LÍNEA · lease autenticado activo en el relay" } else if device.online == Some(false) { "DESCONECTADO · los sobres cifrados esperarán en el buzón" } else { "PRESENCIA DESCONOCIDA · vuelve a verificar al destinatario" }
                                                }
                                            }
                                            if device.trust != PeerTrust::Trusted {
                                                button { class: "button button-quiet trust-button", disabled: busy(), onclick: {
                                                    let device_id = device.device_id.clone();
                                                    let wallet_value = device.wallet.clone();
                                                    let hash = device.identity_key_hash.clone();
                                                    move |_| {
                                                        let device_id = device_id.clone();
                                                        let wallet_value = wallet_value.clone();
                                                        let hash = hash.clone();
                                                        let controller = { session.write().take() };
                                                        let Some(mut controller) = controller else { return; };
                                                        let expected_wallet = controller.wallet().to_string();
                                                        let operation_epoch = wallet_epoch();
                                                        if !operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet) { return; }
                                                        let wallet_signal = wallet;
                                                        let epoch_signal = wallet_epoch;
                                                        let session = session;
                                                        let mut peer_devices = peer_devices;
                                                        let mut status = status;
                                                        let mut status_is_error = status_is_error;
                                                        let mut busy = busy;
                                                        spawn(async move {
                                                            busy.set(true);
                                                            let result = controller.trust_peer(&wallet_value, &device_id, &hash).await;
                                                            if !operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet) { return; }
                                                            match result {
                                                                Ok(()) => {
                                                                    let inspect_result = controller.inspect_peer(&wallet_value).await;
                                                                    if !operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet) { return; }
                                                                    match inspect_result {
                                                                        Ok(devices) => {
                                                                            if recipient().trim().eq_ignore_ascii_case(&wallet_value) { peer_devices.set(devices); }
                                                                            status.set("Huella confirmada por ti. La clave queda asociada a esta wallet y dispositivo localmente.".into());
                                                                            status_is_error.set(false);
                                                                        }
                                                                        Err(error) => { status.set(error); status_is_error.set(true); }
                                                                    }
                                                                }
                                                                Err(error) => { status.set(error); status_is_error.set(true); }
                                                            }
                                                            restore_chat_session(session, view, saved_peer_wallets, controller);
                                                            busy.set(false);
                                                        });
                                                    }
                                                }, if device.trust == PeerTrust::Changed { if english { "Confirm new fingerprint after comparing it" } else { "Confirmar nueva huella tras compararla" } } else { if english { "I confirmed this fingerprint through another channel" } else { "Confirmé esta huella por otro canal" } } }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !pending_senders.is_empty() {
                        div { class: "secure-chat-warning",
                            strong { if english { "Senders whose fingerprints still need verification:" } else { "Remitentes cuya huella aún debes verificar:" } }
                            for sender in pending_senders.clone() {
                                button { class: "text-action", onclick: move |_| set_recipient_target(recipient, peer_devices, selected_device, sender.clone()), if english { "{short_wallet(&sender)} · inspect" } else { "{short_wallet(&sender)} · inspeccionar" } }
                            }
                            span { if english { "Compare the fingerprint through another channel before confirming it. To prevent spam, messages sent before verification are not retained; ask the sender to send them again afterward." } else { "Compara la huella por otro canal antes de confirmarla. Para evitar spam, el contenido enviado antes de verificar no se conserva; pide que lo reenvíen después." } }
                        }
                    }

                    div { class: "secure-chat-card secure-chat-compose",
                        span { class: "section-kicker", if english { "ENCRYPTED MESSAGE · OFF-CHAIN" } else { "MENSAJE CIFRADO · FUERA DE LA CADENA" } }
                        label { class: "field-label", if english { "MESSAGE · UP TO 4096 CHARACTERS" } else { "CONTENIDO · HASTA 4096 CARACTERES" } }
                        textarea { class: "text-field secure-chat-textarea", maxlength: "4096", placeholder: if english { "Write a private message…" } else { "Escribe un mensaje privado…" }, value: draft(), oninput: move |event| draft.set(event.value()), aria_label: if english { "End-to-end encrypted message" } else { "Mensaje cifrado de extremo a extremo" } }
                        div { class: "secure-chat-compose-footer",
                            span { class: "secure-chat-note", if english { "{draft().chars().count()} / 4096 · every message uses random keys and IVs authenticated by the ratchet" } else { "{draft().chars().count()} / 4096 · cada mensaje usa claves e IV aleatorios autenticados por el ratchet" } }
                            button { class: "button button-primary", disabled: busy() || !registered || !sepolia || selected_device().is_empty() || draft().trim().is_empty(), onclick: send_click, if foreground_busy { if english { "Processing…" } else { "Procesando…" } } else { if english { "Encrypt and send ↗" } else { "Cifrar y enviar ↗" } } }
                        }
                        p { class: "secure-chat-note", if english { "The relay receives ciphertext and minimal routing metadata. The body and alias are encrypted; delivery needs no testnet ETH or transaction." } else { "El relay recibe ciphertext y metadatos mínimos para enrutarlo. El cuerpo y el alias van cifrados; sin ETH de testnet y sin transacción para entregar." } }
                    }

                    div { class: "secure-chat-card secure-chat-inbox",
                        div { class: "secure-chat-inbox-heading",
                            div { span { class: "section-kicker", if english { "PRIVATE HISTORY · LAST 72 HOURS" } else { "HISTORIAL PRIVADO · ÚLTIMAS 72 HORAS" } } h3 { if recipient().trim().is_empty() { if english { "Select a conversation" } else { "Selecciona una conversación" } } else { "{peer_display_name(&contacts_snapshot, &recipient())}" } } }
                            span { class: "secure-chat-count", "{local_messages.len()}" }
                        }
                        p { class: "secure-chat-inbox-note", if english { "Scroll through this peer's local messages. Bodies older than 72 hours are deleted automatically with no NODO archive or recovery; device/browser remnants and the recipient's copy cannot be guaranteed erased. A closed browser cleans up on the next unlock." } else { "Desplázate por los mensajes locales de esta wallet. Los cuerpos anteriores a 72 horas se eliminan automáticamente sin archivo ni recuperación en NODO; no se garantiza borrar restos del dispositivo/navegador ni la copia del destinatario. Si cierras el navegador, se limpia al desbloquear de nuevo." } }
                        if local_messages.is_empty() {
                            p { class: "secure-chat-empty", if english { "No retained messages for this peer. Select a saved conversation or recipient; older deleted messages cannot be recovered from blockchain hashes." } else { "No hay mensajes conservados de esta wallet. Selecciona una conversación guardada o un destinatario; los mensajes eliminados no se recuperan desde hashes de la blockchain." } }
                        } else {
                            div { class: "secure-chat-message-list", tabindex: "0", role: "region", aria_label: if english { "Scrollable private message history for selected peer" } else { "Historial privado desplazable de la wallet seleccionada" },
                                for message in local_messages.clone() {
                                    div { key: "{message.envelope_id}", class: if message.outgoing { "secure-message outgoing" } else { "secure-message incoming" },
                                        div { class: "secure-message-head",
                                            strong { "{message_display_name(&contacts_snapshot, &message, english)}" }
                                            code { class: "secure-message-wallet", if message.outgoing { "{message.peer_wallet}" } else { "{message.sender_wallet}" } }
                                            if !message.sender_alias.is_empty() { span { class: "secure-message-alias", if english { "Encrypted alias: {message.sender_alias}" } else { "Alias cifrado: {message.sender_alias}" } } }
                                        }
                                        p { class: "secure-message-body", "{message.body}" }
                                        div { class: "secure-message-timestamps",
                                            div { class: "secure-message-stamp",
                                                span { class: "secure-message-time-label", if english { "SENT · SENDER DEVICE · UTC" } else { "ENVIADO · DISPOSITIVO EMISOR · UTC" } }
                                                if let Some(sent_at) = message.display_sent_at() { time { "{format_time(sent_at, english)}" } }
                                                else { span { class: "secure-chat-note", if english { "Sender time unavailable: invalid or beyond allowed clock skew." } else { "Hora del emisor no disponible: inválida o fuera del desfase permitido." } } }
                                            }
                                            div { class: "secure-message-stamp",
                                                span { class: "secure-message-time-label", "{received_timestamp_label(message.outgoing, &message.status, visible_received_timestamp(message.outgoing, &message.status, message.received_at).is_some(), english)}" }
                                                if let Some(received_at) = visible_received_timestamp(message.outgoing, &message.status, message.received_at) { time { "{format_time(received_at, english)}" } }
                                            }
                                        }
                                        div { class: "secure-message-footer",
                                            span { class: delivery_status_class(&message.status), "{delivery_status_label(&message.status, english)}" }
                                            code { "Keccak {short_hash(&message.ciphertext_hash)}" }
                                            if let Some(tx_hash) = message.anchor_tx.as_ref() { a { class: "secure-message-anchor", href: "https://sepolia.etherscan.io/tx/{tx_hash}", target: "_blank", rel: "noreferrer", if message.anchor_confirmed || message.anchor_status.as_deref() == Some("confirmed") { if english { "Anchor confirmed ↗" } else { "Anclaje confirmado ↗" } } else if message.anchor_status.as_deref() == Some("failed") { if english { "Transaction reverted ↗" } else { "Transacción revertida ↗" } } else if message.anchor_status.as_deref() == Some("pending") { if english { "Anchor pending ↗" } else { "Anclaje pendiente ↗" } } else { if english { "Receipt unverified ↗" } else { "Receipt sin verificar ↗" } } } }
                                            if message.outgoing && message.status == "queued" {
                                                button { class: "copy-button", disabled: busy(), onclick: {
                                                    let envelope_id = message.envelope_id.clone();
                                                    let retry_body = message.body.clone();
                                                    let retry_recipient = message.peer_wallet.clone();
                                                    move |_| {
                                                        let envelope_id = envelope_id.clone();
                                                        let retry_body = retry_body.clone();
                                                        let retry_recipient = retry_recipient.clone();
                                                        let controller = { session.write().take() };
                                                        let Some(mut controller) = controller else { return; };
                                                        let expected_wallet = controller.wallet().to_string();
                                                        let operation_epoch = wallet_epoch();
                                                        if !operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet) { return; }
                                                        let wallet_signal = wallet;
                                                        let epoch_signal = wallet_epoch;
                                                        let session = session;
                                                        let mut status = status;
                                                        let mut status_is_error = status_is_error;
                                                        let mut draft = draft;
                                                        let current_recipient = recipient;
                                                        let mut busy = busy;
                                                        spawn(async move {
                                                            busy.set(true);
                                                            let result = controller.retry_outbox(&envelope_id).await;
                                                            if !operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet) { return; }
                                                            match result {
                                                                Ok(outcome) => {
                                                                    if should_clear_draft_after_send(&outcome.status)
                                                                        && draft.read().trim() == retry_body.as_str()
                                                                        && current_recipient.read().eq_ignore_ascii_case(&retry_recipient)
                                                                    {
                                                                        draft.set(String::new());
                                                                    }
                                                                    status_is_error.set(send_outcome_is_error(&outcome.status));
                                                                    status.set(send_outcome_message(&outcome.status, outcome.warning, english));
                                                                }
                                                                Err(error) => { status.set(error); status_is_error.set(true); }
                                                            }
                                                            restore_chat_session(session, view, saved_peer_wallets, controller);
                                                            busy.set(false);
                                                        });
                                                    }
                                                }, if english { "Retry" } else { "Reintentar" } }
                                            }
                                            if message.outgoing && (message.anchor_tx.is_none() || message.anchor_status.as_deref() == Some("failed")) {
                                                button { class: "copy-button", disabled: busy() || !can_anchor, title: if english { "Anchoring makes wallets, timestamp and ciphertext hash public on Sepolia." } else { "Anclar publica wallets, tiempo y hash del ciphertext en Sepolia." }, onclick: {
                                                    let envelope_id = message.envelope_id.clone();
                                                    let to = message.peer_wallet.clone();
                                                    let hash = message.ciphertext_hash.clone();
                                                    let contract = contract_address();
                                                    let anchor_generation = operation_generation.clone();
                                                    move |_| {
                                                        let envelope_id = envelope_id.clone();
                                                        let to = to.clone();
                                                        let hash = hash.clone();
                                                        let contract = contract.clone();
                                                        let controller = { session.write().take() };
                                                        let Some(mut controller) = controller else { return; };
                                                        let expected_wallet = controller.wallet().to_string();
                                                        let operation_epoch = wallet_epoch();
                                                        let expected_network_epoch = network_epoch();
                                                        let expected_chain = chain_id();
                                                        let expected_contract = contract.clone();
                                                        let generation = anchor_generation.clone();
                                                        let expected_generation = generation.load(Ordering::SeqCst);
                                                        if !anchor_operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet, network_epoch, expected_network_epoch, chain_id, &expected_chain, contract_address, &expected_contract, &generation, expected_generation) {
                                                            if operation_is_current(wallet, wallet_epoch, operation_epoch, &expected_wallet) && generation.load(Ordering::SeqCst) == expected_generation { restore_chat_session(session, view, saved_peer_wallets, controller); }
                                                            return;
                                                        }
                                                        let wallet_signal = wallet;
                                                        let epoch_signal = wallet_epoch;
                                                        let network_epoch_signal = network_epoch;
                                                        let chain_signal = chain_id;
                                                        let contract_signal = contract_address;
                                                        let session = session;
                                                        let mut status = status;
                                                        let mut status_is_error = status_is_error;
                                                        let mut busy = busy;
                                                        spawn(async move {
                                                            busy.set(true);
                                                            if !anchor_operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet, network_epoch_signal, expected_network_epoch, chain_signal, &expected_chain, contract_signal, &expected_contract, &generation, expected_generation) {
                                                                if operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet) && generation.load(Ordering::SeqCst) == expected_generation { restore_chat_session(session, view, saved_peer_wallets, controller); }
                                                                busy.set(false);
                                                                return;
                                                            }
                                                            status.set("El anclaje publicará permanentemente las dos wallets y el hash del ciphertext. Confirma solo si aceptas esa exposición.".into());
                                                            status_is_error.set(false);
                                                            match wallet_bridge::send_message(&contract, &to, &hash, "0", &expected_wallet).await {
                                                                Ok(tx_hash) => {
                                                                    if !anchor_operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet, network_epoch_signal, expected_network_epoch, chain_signal, &expected_chain, contract_signal, &expected_contract, &generation, expected_generation) {
                                                                        if operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet) && generation.load(Ordering::SeqCst) == expected_generation { restore_chat_session(session, view, saved_peer_wallets, controller); }
                                                                        busy.set(false);
                                                                        return;
                                                                    }
                                                                    let receipt = wallet_bridge::wait_for_receipt(&tx_hash).await;
                                                                    if !anchor_operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet, network_epoch_signal, expected_network_epoch, chain_signal, &expected_chain, contract_signal, &expected_contract, &generation, expected_generation) {
                                                                        if operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet) && generation.load(Ordering::SeqCst) == expected_generation { restore_chat_session(session, view, saved_peer_wallets, controller); }
                                                                        busy.set(false);
                                                                        return;
                                                                    }
                                                                    let (anchor_status, summary, failed) = match receipt.as_deref() {
                                                                        Ok("confirmed") => ("confirmed", format!("Anclaje confirmado en Sepolia: {tx_hash}"), false),
                                                                        Ok("failed") => ("failed", format!("La transacción {tx_hash} fue revertida en Sepolia; puedes reintentar el anclaje."), true),
                                                                        Ok("pending") => ("pending", format!("No hubo recibo tras tres minutos. El hash quedó guardado como pendiente: {tx_hash}"), true),
                                                                        Ok(_) => ("unknown", format!("MetaMask devolvió un estado desconocido para {tx_hash}; verifica Etherscan antes de continuar."), true),
                                                                        Err(error) => ("pending", format!("No se pudo consultar el receipt ({error}). El hash quedó guardado como pendiente: {tx_hash}"), true),
                                                                    };
                                                                    let save_result = controller.set_anchor_tx(&envelope_id, &tx_hash, anchor_status).await;
                                                                    if !anchor_operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet, network_epoch_signal, expected_network_epoch, chain_signal, &expected_chain, contract_signal, &expected_contract, &generation, expected_generation) {
                                                                        if operation_is_current(wallet_signal, epoch_signal, operation_epoch, &expected_wallet) && generation.load(Ordering::SeqCst) == expected_generation { restore_chat_session(session, view, saved_peer_wallets, controller); }
                                                                        busy.set(false);
                                                                        return;
                                                                    }
                                                                    match save_result {
                                                                        Ok(()) => { status.set(summary); status_is_error.set(failed); }
                                                                        Err(error) => { status.set(format!("{summary} No se pudo guardar el estado local: {error}")); status_is_error.set(true); }
                                                                    }
                                                                }
                                                                Err(error) => { status.set(error); status_is_error.set(true); }
                                                            }
                                                            restore_chat_session(session, view, saved_peer_wallets, controller);
                                                            busy.set(false);
                                                        });
                                                    }
                                                }, if message.anchor_status.as_deref() == Some("failed") { if english { "Retry anchor" } else { "Reintentar anclaje" } } else { if english { "Anchor hash · optional" } else { "Anclar hash · opcional" } } }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        p { class: "secure-chat-disclosure", if english { "Privacy: the server can observe wallets, pseudonymous devices, time, size and IP address. It cannot decrypt message bodies. An alias does not provide anonymity. Blockchain anchoring is optional and permanently makes wallets, time and ciphertext hash public; it may require Sepolia gas." } else { "Privacidad: el servidor puede observar wallets, dispositivos seudónimos, hora, tamaño e IP. No puede descifrar el cuerpo. Un alias no da anonimato. El anclaje blockchain es opcional y hace públicos para siempre las wallets, la hora y el hash del ciphertext; puede requerir gas de Sepolia." } }
                    }
                }
            }
        }
    }
}

fn operation_is_current(
    wallet: Signal<Option<String>>,
    wallet_epoch: Signal<u64>,
    expected_epoch: u64,
    expected_wallet: &str,
) -> bool {
    wallet_epoch() == expected_epoch
        && wallet()
            .as_deref()
            .is_some_and(|active| active.eq_ignore_ascii_case(expected_wallet))
}

fn set_recipient_target(
    mut recipient: Signal<String>,
    mut peer_devices: Signal<Vec<PeerDeviceInfo>>,
    mut selected_device: Signal<String>,
    value: String,
) {
    recipient.set(value);
    peer_devices.set(Vec::new());
    selected_device.set(String::new());
}

fn peer_display_name(contacts: &[(String, String)], wallet: &str) -> String {
    contacts
        .iter()
        .find(|(_, address)| address.eq_ignore_ascii_case(wallet))
        .map(|(name, _)| format!("{name} · {}", short_wallet(wallet)))
        .unwrap_or_else(|| short_wallet(wallet))
}

fn messages_for_peer(messages: &[LocalChatMessage], peer: &str) -> Vec<LocalChatMessage> {
    let mut selected = messages
        .iter()
        .filter(|message| message.peer_wallet.eq_ignore_ascii_case(peer))
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by_key(LocalChatMessage::history_sort_timestamp);
    selected
}

fn anchor_operation_is_current(
    wallet: Signal<Option<String>>,
    wallet_epoch: Signal<u64>,
    expected_wallet_epoch: u64,
    expected_wallet: &str,
    network_epoch: Signal<u64>,
    expected_network_epoch: u64,
    chain_id: Signal<String>,
    expected_chain: &str,
    contract_address: Signal<String>,
    expected_contract: &str,
    generation: &OperationGeneration,
    expected_generation: u64,
) -> bool {
    operation_is_current(wallet, wallet_epoch, expected_wallet_epoch, expected_wallet)
        && network_epoch() == expected_network_epoch
        && chain_id().eq_ignore_ascii_case(expected_chain)
        && contract_address().eq_ignore_ascii_case(expected_contract)
        && generation.load(Ordering::SeqCst) == expected_generation
}

fn localized_secure_status(message: &str, english: bool) -> String {
    if !english {
        return message.to_string();
    }
    let translated = match message {
        "La wallet cambió o se desconectó. El perfil y el borrador privados quedaron bloqueados y borrados de la interfaz." => "Wallet changed or disconnected. The private profile and draft were locked and cleared from the interface.",
        "Conecta MetaMask antes de abrir el perfil E2EE." => "Connect MetaMask before opening the E2EE profile.",
        "Escribe la contraseña local para cifrar o desbloquear el perfil." => "Enter the local password to encrypt or unlock the profile.",
        "Cambia MetaMask a Ethereum Sepolia para vincular esta identidad de wallet." => "Switch MetaMask to Ethereum Sepolia to bind this wallet identity.",
        "Perfil local desbloqueado. La contraseña no se envía al relay." => "Local profile unlocked. The password is never sent to the relay.",
        "Perfil E2EE creado y cifrado en IndexedDB. Firma EIP-712 para publicarlo en el relay." => "E2EE profile created and encrypted in IndexedDB. Sign an EIP-712 message to publish its public bundle to the relay.",
        "Desbloquea primero el perfil E2EE." => "Unlock the E2EE profile first.",
        "Identidad vinculada por 365 días y bundles públicos registrados. La firma no consume gas; la sesión del relay dura 12 horas y el lease de presencia está activo." => "Identity bound for 365 days and public bundles registered. The signature costs no gas; the relay session lasts 12 hours and presence is active.",
        "Identidad vinculada y bundles públicos registrados. El relay no confirmó presencia todavía; NODO volverá a intentarlo automáticamente." => "Identity bound and public bundles registered. The relay has not confirmed presence yet; NODO will retry automatically.",
        "Desbloquea el perfil y registra el dispositivo antes de verificar contactos." => "Unlock the profile and register this device before verifying contacts.",
        "Escribe una wallet EVM válida para inspeccionar su identidad." => "Enter a valid EVM wallet to inspect its identity.",
        "Bundle verificado criptográficamente. Compara la huella por otro canal antes de marcarla como verificada." => "Bundle verified cryptographically. Compare the fingerprint through another channel before marking it as verified.",
        "Desbloquea y registra el perfil E2EE antes de enviar." => "Unlock and register the E2EE profile before sending.",
        "Ciphertext entregado al relay. El mensaje no se publicó on-chain ni requiere ETH." => "Ciphertext delivered to the relay. The message was not published on-chain and needs no ETH.",
        "Mensaje cifrado guardado en la cola local para reintentar." => "Encrypted message saved in the local retry queue.",
        "Desbloquea el perfil y registra el dispositivo para consultar la bandeja." => "Unlock the profile and register this device to check the inbox.",
        "Desbloquea el perfil antes de guardar tu alias." => "Unlock the profile before saving your alias.",
        "Alias guardado en el perfil local cifrado; se compartirá solo dentro del mensaje cifrado." => "Alias saved in the encrypted local profile; it will only be shared inside encrypted messages.",
        "Perfil bloqueado. Las claves privadas solo estarán disponibles al desbloquearlo otra vez." => "Profile locked. Private keys will only be available after unlocking again.",
        "Huella confirmada por ti. La clave queda asociada a esta wallet y dispositivo localmente." => "Fingerprint confirmed by you. This key is now locally associated with this wallet and device.",
        "Mensaje cifrado aceptado por el relay." => "Encrypted message accepted by the relay.",
        "La wallet cambió o el perfil se bloqueó durante la operación." => "The wallet changed or the profile was locked during the operation.",
        "La versión del perfil E2EE no es compatible con esta aplicación." => "This application does not support this E2EE profile version.",
        "El perfil local no contiene un identificador de dispositivo válido." => "The local profile does not contain a valid device identifier.",
        "Para crear un perfil nuevo, usa una contraseña local de al menos 12 caracteres." => "To create a new profile, use a local password of at least 12 characters.",
        "El relay devolvió un challenge EIP-712 distinto del formato NODO esperado; no se pidió firma." => "The relay returned an EIP-712 challenge that does not match the expected NODO format; no signature was requested.",
        "El challenge EIP-712 venció o el reloj del dispositivo está adelantado. Sincroniza fecha y hora y vuelve a vincular; no se pidió firma." => "The EIP-712 challenge expired or your device clock is ahead. Sync your date and time and bind again; no signature was requested.",
        "El challenge EIP-712 excede la vigencia permitida o el reloj del dispositivo está atrasado más de 60 segundos. Sincroniza fecha y hora y vuelve a vincular; no se pidió firma." => "The EIP-712 challenge exceeds the allowed lifetime or your device clock is over 60 seconds behind. Sync your date and time and bind again; no signature was requested.",
        "La firma de MetaMask no corresponde a esta wallet; no se registró el dispositivo." => "The MetaMask signature does not match this wallet; the device was not registered.",
        "El relay devolvió una sesión de wallet incompleta o incompatible." => "The relay returned an incomplete or incompatible wallet session.",
        "El dispositivo ya no está publicado para esa wallet." => "That device is no longer published for this wallet.",
        "La huella cambió mientras revisabas el contacto. Vuelve a inspeccionar la wallet." => "The fingerprint changed while you were reviewing this contact. Inspect the wallet again.",
        "El alias debe tener como máximo 48 caracteres." => "The alias must be 48 characters or fewer.",
        "Elige otra wallet; no puedes enviarte un mensaje a tu propia dirección." => "Choose another wallet; you cannot message your own address.",
        "No se encontró ese dispositivo registrado de la wallet destinataria." => "That registered device for the recipient wallet was not found.",
        "El destinatario no tiene prekeys de un solo uso disponibles. Pídele que abra NODO, desbloquee y registre su dispositivo." => "The recipient has no one-time prekeys available. Ask them to open NODO, unlock, and register their device.",
        "El perfil perdió el estado local de esta conversación. No se intentará enviar un mensaje incompatible." => "The profile lost this conversation's local state. An incompatible message will not be sent.",
        "El relay devolvió una prekey para una wallet/dispositivo distinto." => "The relay returned a prekey for a different wallet or device.",
        "No se encontró el mensaje pendiente en la cola local." => "The pending message was not found in the local queue.",
        "La sesión del relay expiró. Vuelve a firmar el acceso para reintentar." => "The relay session expired. Sign in again to retry.",
        "El sobre cifrado pendiente no está disponible." => "The pending encrypted envelope is unavailable.",
        "El relay devolvió un recibo distinto del mensaje enviado." => "The relay returned a receipt for a different message.",
        "El estado de anclaje local no es válido." => "The local anchor state is invalid.",
        "No se encontró el mensaje local para actualizar su anclaje." => "The local message to update with this anchor was not found.",
        "El relay devolvió bundles para una wallet distinta." => "The relay returned bundles for a different wallet.",
        "La huella del relay no coincide con su clave de identidad pública." => "The relay fingerprint does not match its public identity key.",
        "La atestación wallet-key remota tiene expiración inválida." => "The remote wallet-key attestation has an invalid expiry.",
        "La atestación wallet-key remota está vencida o tiene una vigencia inválida." => "The remote wallet-key attestation is expired or has an invalid validity period.",
        "La dirección debe tener el formato EVM 0x + 40 caracteres hexadecimales." => "The address must use the EVM format: 0x followed by 40 hexadecimal characters.",
        "No hay dispositivo publicado para esa wallet. La otra persona debe crear su perfil, conectar Sepolia y registrar su dispositivo." => "No device is published for that wallet. The other person must create a profile, connect to Sepolia, and register their device.",
        "El anclaje publicará permanentemente las dos wallets y el hash del ciphertext. Confirma solo si aceptas esa exposición." => "Anchoring permanently publishes both wallets and the ciphertext hash. Confirm only if you accept this exposure.",
        _ => return translate_dynamic_status(message),
    };
    translated.to_string()
}

fn translate_dynamic_status(message: &str) -> String {
    for (spanish, english) in [
        (
            "El estado local cifrado no es válido: ",
            "The encrypted local state is invalid: ",
        ),
        (
            "La prueba interna de identidad del dispositivo falló: ",
            "The device's internal identity proof failed: ",
        ),
        (
            "La firma de la prekey del destinatario no es válida: ",
            "The recipient's prekey signature is invalid: ",
        ),
        (
            "No se pudo iniciar la sesión Olm del destinatario: ",
            "Could not start the recipient's Olm session: ",
        ),
        (
            "No se pudo guardar el punto de restauración del ratchet: ",
            "Could not save the ratchet recovery point: ",
        ),
        (
            "No se pudo restaurar el ratchet tras un mensaje inválido: ",
            "Could not restore the ratchet after an invalid message: ",
        ),
        (
            "La clave de identidad remota no es válida: ",
            "The remote identity key is invalid: ",
        ),
        (
            "La firma Ed25519 de la identidad remota no es válida: ",
            "The remote Ed25519 identity signature is invalid: ",
        ),
    ] {
        if let Some(detail) = message.strip_prefix(spanish) {
            return format!("{english}{detail}");
        }
    }
    if let Some(detail) = message.strip_prefix(
        "La reserva de prekey expiró; NODO la renovó automáticamente con una sesión y OTK nuevas. ",
    ) {
        return format!("The prekey reservation expired; NODO renewed it automatically with a fresh session and one-time key. {detail}");
    }
    if let Some(detail) =
        message.strip_prefix("La reserva anterior expiró; se creó un nuevo sobre cifrado. ")
    {
        return format!(
            "The previous reservation expired; a new encrypted envelope was created. {detail}"
        );
    }
    if message == "La reserva anterior expiró; el mensaje se volvió a cifrar y el relay aceptó el nuevo sobre." {
        return "The previous reservation expired; the message was re-encrypted and the relay accepted the new envelope.".to_string();
    }
    if message == "La reserva anterior expiró; el mensaje se volvió a cifrar y quedó en la cola local para reintentar." {
        return "The previous reservation expired; the message was re-encrypted and queued locally for retry.".to_string();
    }
    if let Some(detail) = message.strip_prefix("El estado E2EE quedó guardado localmente, pero el relay aún no confirmó la entrega o el último guardado falló: ") {
        return format!("The E2EE state was saved locally, but the relay has not confirmed delivery or the latest save failed: {detail}");
    }
    if let Some(detail) = message.strip_prefix("MetaMask devolvió un estado desconocido para ") {
        return format!("MetaMask returned an unknown status for {detail}").replace(
            "; verifica Etherscan antes de continuar.",
            "; check Etherscan before continuing.",
        );
    }
    if let Some(detail) = message.strip_prefix("No se pudo consultar el receipt (") {
        return format!("Could not query the receipt ({detail}").replace(
            "). El hash quedó guardado como pendiente: ",
            "). The hash is saved as pending: ",
        );
    }
    if let Some(detail) = message.strip_prefix("Anclaje confirmado en Sepolia: ") {
        return format!("Anchor confirmed on Sepolia: {detail}");
    }
    if let Some(detail) = message.strip_prefix("La transacción ") {
        return format!("Transaction {detail}").replace(
            " fue revertida en Sepolia; puedes reintentar el anclaje.",
            " was reverted on Sepolia; you can retry anchoring.",
        );
    }
    if let Some(detail) = message
        .strip_prefix("No hubo recibo tras tres minutos. El hash quedó guardado como pendiente: ")
    {
        return format!(
            "No receipt arrived after three minutes. The hash remains pending: {detail}"
        );
    }
    if message.starts_with("El anclaje publicará permanentemente") {
        return "Anchoring permanently publishes both wallets and the ciphertext hash. Confirm only if you accept this exposure.".to_string();
    }
    if looks_like_spanish_status(message) {
        return "The operation could not be completed. Switch to Spanish to view the detailed diagnostic.".to_string();
    }
    message.to_string()
}

fn delivery_status_class(status: &str) -> &'static str {
    match status {
        "delivered" | "received" | "sent" => "secure-message-state ok",
        "rejected"
        | "replaced"
        | "expired"
        | "relay_rejected"
        | "integrity_error"
        | "integrity_unverified" => "secure-message-state error",
        _ => "secure-message-state pending",
    }
}

fn delivery_status_label(status: &str, english: bool) -> &'static str {
    match (status, english) {
        ("waiting_online", true) => "NO ACTIVE RECIPIENT LEASE · CIPHERTEXT QUEUED",
        ("waiting_online", false) => "SIN LEASE ACTIVO DEL DESTINATARIO · CIPHERTEXT EN COLA",
        ("awaiting_delivery", true) => "RECIPIENT LEASE ACTIVE · HASH-BOUND ACK PENDING",
        ("awaiting_delivery", false) => {
            "LEASE DEL DESTINATARIO ACTIVO · ACK LIGADO AL HASH PENDIENTE"
        }
        ("delivered", true) => "DELIVERED · CIPHERTEXT HASH VERIFIED",
        ("delivered", false) => "ENTREGADO · HASH DEL CIPHERTEXT VERIFICADO",
        ("rejected", true) => "REJECTED BY RECIPIENT · ACK AUTHENTICATED",
        ("rejected", false) => "RECHAZADO POR EL DESTINATARIO · ACK AUTENTICADO",
        ("relay_rejected", true) => "RELAY REJECTED · DELIVERY NOT ACCEPTED",
        ("relay_rejected", false) => "RELAY RECHAZÓ · ENTREGA NO ACEPTADA",
        ("integrity_error", true) => "INTEGRITY ERROR · DO NOT TRUST DELIVERY",
        ("integrity_error", false) => "ERROR DE INTEGRIDAD · NO CONFÍES EN LA ENTREGA",
        ("integrity_unverified", true) => "STATUS UNVERIFIED · NO HASH-VERIFIED ACK",
        ("integrity_unverified", false) => "ESTADO SIN VERIFICAR · SIN ACK VALIDADO POR HASH",
        ("expired", true) => "EXPIRED · COMPOSE A NEW MESSAGE",
        ("expired", false) => "EXPIRADO · REDACTA UN MENSAJE NUEVO",
        ("received", true) => "E2EE · AUTHENTICATED ON THIS DEVICE",
        ("received", false) => "E2EE · AUTENTICADO EN ESTE DISPOSITIVO",
        ("sent", true) => "CIPHERTEXT ACCEPTED BY RELAY",
        ("sent", false) => "CIPHERTEXT ACEPTADO POR EL RELAY",
        ("replaced", true) => "OLD ENVELOPE EXPIRED · MESSAGE RE-ENCRYPTED",
        ("replaced", false) => "SOBRE ANTERIOR EXPIRADO · MENSAJE CIFRADO DE NUEVO",
        ("queued", true) => "LOCAL QUEUE · PENDING RELAY ACCEPTANCE",
        ("queued", false) => "COLA LOCAL · PENDIENTE DE ACEPTACIÓN DEL RELAY",
        (_, true) => "DELIVERY STATUS UNKNOWN",
        (_, false) => "ESTADO DE ENTREGA DESCONOCIDO",
    }
}

fn looks_like_spanish_status(message: &str) -> bool {
    message
        .chars()
        .any(|character| matches!(character, 'á' | 'é' | 'í' | 'ó' | 'ú' | 'ñ' | '¿' | '¡'))
        || [
            "El ",
            "La ",
            "No se ",
            "No hay ",
            "No se encontró",
            "Escribe ",
            "Conecta ",
            "Desbloquea ",
            "Cambia ",
            "Pega ",
            "Verifica ",
            "Confirma ",
            "Pulsa ",
            "Pide ",
            "Perfil ",
            "Mensaje ",
            "Identidad ",
            "Huella ",
            "Bundle ",
            "Contacto ",
            "Anclaje ",
            "Wallet conectada",
        ]
        .iter()
        .any(|prefix| message.starts_with(prefix))
}

#[cfg(test)]
mod locale_tests {
    use super::*;

    #[test]
    fn english_mode_translates_dynamic_relay_errors() {
        assert_eq!(
            localized_secure_status(
                "El relay devolvió un recibo distinto del mensaje enviado.",
                true
            ),
            "The relay returned a receipt for a different message."
        );
        assert_eq!(
            localized_secure_status(
                "La clave de identidad remota no es válida: invalid key",
                true
            ),
            "The remote identity key is invalid: invalid key"
        );
        assert_eq!(
            localized_secure_status(
                "Identidad vinculada por 365 días y bundles públicos registrados. La firma no consume gas; la sesión del relay dura 12 horas y el lease de presencia está activo.",
                true
            ),
            "Identity bound for 365 days and public bundles registered. The signature costs no gas; the relay session lasts 12 hours and presence is active."
        );
        assert_eq!(
            localized_secure_status(
                "Identidad vinculada y bundles públicos registrados. El relay no confirmó presencia todavía; NODO volverá a intentarlo automáticamente.",
                true
            ),
            "Identity bound and public bundles registered. The relay has not confirmed presence yet; NODO will retry automatically."
        );
    }

    #[test]
    fn unknown_spanish_diagnostics_use_an_english_fallback() {
        let diagnostic = "El relay devolvió un error nuevo.";
        assert!(localized_secure_status(diagnostic, true)
            .starts_with("The operation could not be completed."));
        assert_eq!(localized_secure_status(diagnostic, false), diagnostic);
    }
}

fn short_wallet(value: &str) -> String {
    if value.len() <= 13 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..6], &value[value.len() - 4..])
    }
}

fn short_device(value: &str) -> String {
    if value.len() <= 13 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..8], &value[value.len() - 4..])
    }
}

fn short_hash(value: &str) -> String {
    if value.len() <= 27 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..10], &value[value.len() - 8..])
    }
}

fn message_display_name(
    contacts: &[(String, String)],
    message: &LocalChatMessage,
    english: bool,
) -> String {
    if message.outgoing {
        return if english { "You" } else { "Tú" }.to_string();
    }
    contacts
        .iter()
        .find(|(_, address)| address.eq_ignore_ascii_case(&message.sender_wallet))
        .map(|(name, _)| name.clone())
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            let alias = message.sender_alias.trim();
            (!alias.is_empty()).then(|| alias.to_string())
        })
        .unwrap_or_else(|| short_wallet(&message.sender_wallet))
}

fn format_time(timestamp_ms: i64, english: bool) -> String {
    if timestamp_ms <= 0 || timestamp_ms > 8_640_000_000_000_000 {
        return if english {
            "time unavailable"
        } else {
            "hora no disponible"
        }
        .to_string();
    }
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(timestamp_ms as f64))
            .to_iso_string()
            .as_string()
            .unwrap_or_else(|| timestamp_ms.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        timestamp_ms.to_string()
    }
}

fn visible_received_timestamp(
    outgoing: bool,
    status: &str,
    received_at: Option<i64>,
) -> Option<i64> {
    let timestamp = received_at?;
    if timestamp <= 0 || timestamp > 8_640_000_000_000_000 {
        return None;
    }
    if outgoing {
        (status == "delivered").then_some(timestamp)
    } else {
        (status == "received").then_some(timestamp)
    }
}

fn received_timestamp_label(
    outgoing: bool,
    status: &str,
    has_timestamp: bool,
    english: bool,
) -> &'static str {
    if has_timestamp {
        return if outgoing {
            if english {
                "RECEIVED · HASH-VERIFIED RELAY ACK · UTC"
            } else {
                "RECIBIDO · ACK DEL RELAY VERIFICADO POR HASH · UTC"
            }
        } else if english {
            "RECEIVED ON THIS DEVICE · UTC"
        } else {
            "RECIBIDO EN ESTE DISPOSITIVO · UTC"
        };
    }
    if !outgoing {
        return if english {
            "RECEIVE TIME UNAVAILABLE"
        } else {
            "HORA DE RECEPCIÓN NO DISPONIBLE"
        };
    }
    match status {
        "delivered" => {
            if english {
                "DELIVERY CONFIRMED · TIME UNAVAILABLE"
            } else {
                "ENTREGA CONFIRMADA · HORA NO DISPONIBLE"
            }
        }
        "rejected" => {
            if english {
                "DELIVERY REJECTED · NO RECEIPT TIME"
            } else {
                "ENTREGA RECHAZADA · SIN HORA DE RECEPCIÓN"
            }
        }
        "relay_rejected" => {
            if english {
                "RELAY REJECTED · NO RECEIPT TIME"
            } else {
                "RELAY RECHAZÓ · SIN HORA DE RECEPCIÓN"
            }
        }
        "expired" => {
            if english {
                "EXPIRED · NO RECEIPT TIME"
            } else {
                "EXPIRADO · SIN HORA DE RECEPCIÓN"
            }
        }
        "integrity_error" => {
            if english {
                "RECEIPT INTEGRITY FAILURE · NO VERIFIED RECEIPT"
            } else {
                "FALLA DE INTEGRIDAD DEL RECIBO · SIN ENTREGA VERIFICADA"
            }
        }
        "integrity_unverified" => {
            if english {
                "RECEIPT HASH UNVERIFIED · NO TIME"
            } else {
                "HASH DEL RECIBO SIN VERIFICAR · SIN HORA"
            }
        }
        _ => {
            if english {
                "RECEIPT PENDING · WAITING FOR HASH-VERIFIED ACK"
            } else {
                "RECEPCIÓN PENDIENTE · ESPERANDO ACK HASH-VERIFICADO"
            }
        }
    }
}

fn send_outcome_is_error(status: &str) -> bool {
    matches!(
        status,
        "rejected" | "expired" | "relay_rejected" | "integrity_error" | "integrity_unverified"
    )
}

fn should_clear_draft_after_send(status: &str) -> bool {
    matches!(
        status,
        "waiting_online" | "awaiting_delivery" | "sent" | "delivered" | "rejected"
    )
}

fn send_outcome_message(status: &str, warning: Option<String>, english: bool) -> String {
    if english {
        return match status {
            "waiting_online" => warning.map(|detail| format!("Ciphertext queued by the relay until the recipient is online. Delivery is not confirmed yet. Relay detail: {detail}"))
                .unwrap_or_else(|| "Ciphertext queued by the relay until the recipient is online. Delivery is not confirmed yet.".into()),
            "awaiting_delivery" | "sent" => warning.map(|detail| format!("Ciphertext accepted by the relay; waiting for the recipient's hash-verified receipt. {detail}"))
                .unwrap_or_else(|| "Ciphertext accepted by the relay; waiting for the recipient's hash-verified receipt.".into()),
            "delivered" => "The recipient device acknowledged the matching ciphertext hash.".into(),
            "queued" => warning.map(|detail| format!("Ciphertext remains in this device's outbox; relay acceptance is not confirmed. Retry later. Relay detail: {detail}"))
                .unwrap_or_else(|| "Ciphertext remains in this device's outbox; relay acceptance is not confirmed. Retry later.".into()),
            "rejected" => "The recipient device rejected the message with an authenticated ACK.".into(),
            "relay_rejected" => format!("The relay permanently rejected this envelope; delivery was not accepted. {}", warning.unwrap_or_else(|| "Check the relay response and compose again.".into())),
            "expired" => "The envelope expired. Compose a new message to send a fresh encrypted envelope.".into(),
            "integrity_error" => "The relay receipt failed an integrity check; delivery is not verified.".into(),
            "integrity_unverified" => "The delivery receipt has no verifiable ciphertext hash.".into(),
            "replaced" => "The expired envelope was replaced by a new encrypted envelope.".into(),
            _ => warning.unwrap_or_else(|| "Encrypted message status updated.".into()),
        };
    }
    match status {
        "waiting_online" => warning.map(|detail| format!("El ciphertext quedó en cola del relay hasta que el destinatario vuelva a estar en línea. La entrega aún no está confirmada. Detalle del relay: {detail}"))
            .unwrap_or_else(|| "El ciphertext quedó en cola del relay hasta que el destinatario vuelva a estar en línea. La entrega aún no está confirmada.".into()),
        "awaiting_delivery" | "sent" => warning.map(|detail| format!("El relay aceptó el ciphertext; espera el recibo del destinatario verificado por hash. {detail}"))
            .unwrap_or_else(|| "El relay aceptó el ciphertext; espera el recibo del destinatario verificado por hash.".into()),
        "delivered" => "El dispositivo destinatario confirmó el hash coincidente del ciphertext.".into(),
        "queued" => warning.map(|detail| format!("El ciphertext sigue en la cola local; el relay aún no confirmó su aceptación. Reintenta más tarde. Detalle del relay: {detail}"))
            .unwrap_or_else(|| "El ciphertext sigue en la cola local; el relay aún no confirmó su aceptación. Reintenta más tarde.".into()),
        "rejected" => "El dispositivo destinatario rechazó el mensaje con un ACK autenticado.".into(),
        "relay_rejected" => format!("El relay rechazó permanentemente este sobre; no se aceptó la entrega. {}", warning.unwrap_or_else(|| "Revisa el error del relay y vuelve a redactar.".into())),
        "expired" => "El sobre expiró. Redacta un mensaje nuevo para enviar un sobre cifrado nuevo.".into(),
        "integrity_error" => "El recibo del relay no pasó la verificación de integridad; la entrega no está verificada.".into(),
        "integrity_unverified" => "El recibo de entrega no incluye un hash de ciphertext verificable.".into(),
        "replaced" => "El sobre expirado se reemplazó por un sobre cifrado nuevo.".into(),
        _ => warning.unwrap_or_else(|| "Se actualizó el estado del mensaje cifrado.".into()),
    }
}

fn trust_class(trust: &PeerTrust) -> &'static str {
    match trust {
        PeerTrust::Trusted => "peer-trust trusted",
        PeerTrust::FirstUse => "peer-trust first-use",
        PeerTrust::Changed => "peer-trust changed",
    }
}

fn trust_label(trust: &PeerTrust, english: bool) -> &'static str {
    match trust {
        PeerTrust::Trusted => {
            if english {
                "FINGERPRINT VERIFIED"
            } else {
                "HUELLA CONFIRMADA"
            }
        }
        PeerTrust::FirstUse => {
            if english {
                "FIRST CONTACT"
            } else {
                "PRIMER CONTACTO"
            }
        }
        PeerTrust::Changed => {
            if english {
                "KEY CHANGED"
            } else {
                "CAMBIO DE CLAVE"
            }
        }
    }
}

#[cfg(test)]
mod received_timestamp_tests {
    use super::received_timestamp_label;

    #[test]
    fn receipt_labels_distinguish_device_time_and_verified_relay_ack() {
        assert_eq!(
            received_timestamp_label(true, "delivered", true, true),
            "RECEIVED · HASH-VERIFIED RELAY ACK · UTC"
        );
        assert_eq!(
            received_timestamp_label(false, "received", true, false),
            "RECIBIDO EN ESTE DISPOSITIVO · UTC"
        );
    }

    #[test]
    fn missing_or_unverified_receipts_never_look_delivered() {
        assert_eq!(
            received_timestamp_label(true, "delivered", false, true),
            "DELIVERY CONFIRMED · TIME UNAVAILABLE"
        );
        assert_eq!(
            received_timestamp_label(true, "queued", false, false),
            "RECEPCIÓN PENDIENTE · ESPERANDO ACK HASH-VERIFICADO"
        );
        assert_eq!(
            received_timestamp_label(true, "integrity_error", false, true),
            "RECEIPT INTEGRITY FAILURE · NO VERIFIED RECEIPT"
        );
        assert_eq!(
            received_timestamp_label(false, "received", false, true),
            "RECEIVE TIME UNAVAILABLE"
        );
    }
}

#[cfg(test)]
mod delivery_display_tests {
    use super::{
        send_outcome_is_error, send_outcome_message, should_clear_draft_after_send,
        visible_received_timestamp,
    };

    #[test]
    fn only_verified_or_locally_received_messages_show_a_receive_time() {
        let received_at = 1_790_000_000_000;
        assert_eq!(
            visible_received_timestamp(true, "delivered", Some(received_at)),
            Some(received_at)
        );
        assert_eq!(
            visible_received_timestamp(true, "awaiting_delivery", Some(received_at)),
            None
        );
        assert_eq!(
            visible_received_timestamp(true, "integrity_error", Some(received_at)),
            None
        );
        assert_eq!(
            visible_received_timestamp(false, "received", Some(received_at)),
            Some(received_at)
        );
        assert_eq!(
            visible_received_timestamp(false, "queued", Some(received_at)),
            None
        );
        assert_eq!(
            visible_received_timestamp(false, "received", Some(-1)),
            None
        );
        assert_eq!(visible_received_timestamp(false, "received", None), None);
    }

    #[test]
    fn relay_accepted_waiting_states_are_not_errors_and_are_localized() {
        assert!(!send_outcome_is_error("waiting_online"));
        assert!(!send_outcome_is_error("awaiting_delivery"));
        assert!(send_outcome_is_error("integrity_error"));
        assert!(send_outcome_is_error("rejected"));
        assert!(send_outcome_message("waiting_online", None, true).contains("queued by the relay"));
        assert!(
            send_outcome_message("awaiting_delivery", None, false).contains("aceptó el ciphertext")
        );
        assert!(should_clear_draft_after_send("waiting_online"));
        assert!(should_clear_draft_after_send("delivered"));
        assert!(!should_clear_draft_after_send("queued"));
        assert!(!should_clear_draft_after_send("relay_rejected"));
    }
}

#[cfg(test)]
mod conversation_history_tests {
    use super::*;
    use serde_json::json;

    fn message(peer: &str, body: &str, created_at: i64) -> LocalChatMessage {
        serde_json::from_value(json!({
            "envelope_id": format!("test-{created_at}"),
            "peer_wallet": peer,
            "peer_device_id": "synthetic-peer-device",
            "sender_wallet": "0x0000000000000000000000000000000000000099",
            "sender_alias": "",
            "body": body,
            "created_at": created_at,
            "outgoing": true,
            "ciphertext_hash": "test-hash",
            "status": "delivered",
            "anchor_tx": null
        }))
        .expect("local message fixture")
    }

    #[test]
    fn selected_conversation_never_shows_another_peers_messages() {
        let all = vec![
            message("0xAB", "latest A", 300),
            message("0xCD", "private B", 200),
            message("0xab", "earlier A", 100),
        ];
        let selected = messages_for_peer(&all, "0xab");
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].body, "earlier A");
        assert_eq!(selected[1].body, "latest A");
        assert!(messages_for_peer(&all, "").is_empty());
        assert!(messages_for_peer(&all, "0xEF").is_empty());
    }

    #[test]
    fn saved_contact_alias_is_local_and_wallet_specific() {
        let contacts = vec![("Alex".into(), "0xAB".into())];
        assert!(peer_display_name(&contacts, "0xab").starts_with("Alex ·"));
        assert!(!peer_display_name(&contacts, "0xCD").contains("Alex"));
    }
}
