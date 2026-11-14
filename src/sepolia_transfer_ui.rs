use dioxus::prelude::*;
use std::sync::atomic::Ordering;

use crate::{secure_messaging::OperationGeneration, wallet_bridge};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferState {
    Idle,
    Review,
    Requesting,
    Pending,
    Confirmed,
    Reverted,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransferContext {
    wallet: Option<String>,
    recipient: String,
    chain_id: String,
    network_epoch: u64,
}

fn text(english: bool, en: &'static str, es: &'static str) -> &'static str {
    if english {
        en
    } else {
        es
    }
}

fn short_address(value: &str) -> String {
    if value.len() <= 13 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..6], &value[value.len() - 4..])
    }
}

fn validate_form(
    english: bool,
    recipient: &str,
    amount: &str,
    wallet: Option<&str>,
    chain_id: &str,
) -> Result<String, String> {
    if !wallet_bridge::is_evm_address(recipient.trim()) {
        return Err(text(
            english,
            "Enter a valid recipient EVM address.",
            "Escribe una dirección EVM válida para el destinatario.",
        )
        .to_string());
    }
    let normalized_amount = match wallet_bridge::normalize_native_amount(amount) {
        Ok(value) => value,
        Err(_) => {
            return Err(text(
                english,
                "Enter an exact positive ETH amount with at most 18 decimal places. Exponents and zero are not accepted.",
                "Escribe un importe ETH decimal exacto, mayor que cero y con hasta 18 decimales. No se aceptan exponentes ni cero.",
            )
            .to_string())
        }
    };
    if wallet.is_none() {
        return Err(text(
            english,
            "Connect an active wallet before transferring.",
            "Conecta una wallet activa antes de transferir.",
        )
        .to_string());
    }
    if !wallet_bridge::is_evm_address(wallet.unwrap_or_default()) {
        return Err(text(
            english,
            "The active account is not a valid EVM address.",
            "La cuenta activa no es una dirección EVM válida.",
        )
        .to_string());
    }
    if !wallet_bridge::is_sepolia_chain_id(chain_id) {
        return Err(text(
            english,
            "Switch MetaMask to Ethereum Sepolia (chainId 11155111).",
            "Cambia MetaMask a Ethereum Sepolia (chainId 11155111).",
        )
        .to_string());
    }
    Ok(normalized_amount)
}

fn localized_bridge_error(error: &str, english: bool) -> String {
    if !english {
        return error.to_string();
    }
    let lower = error.to_ascii_lowercase();
    if lower.contains("revirti") {
        "The Sepolia transaction reverted. No automatic retry was made.".to_string()
    } else if lower.contains("rechaz") || lower.contains("reject") {
        "MetaMask rejected the ETH transfer. No transaction was submitted by NODO.".to_string()
    } else if lower.contains("cuenta") || lower.contains("account") {
        "The active MetaMask account changed. Review the recipient and wallet before trying again."
            .to_string()
    } else if lower.contains("sepolia") || lower.contains("chain") {
        "MetaMask is not on Ethereum Sepolia (chainId 11155111).".to_string()
    } else {
        format!("Transfer error: {error}")
    }
}

fn transfer_operation_is_current(
    wallet: Signal<Option<String>>,
    chain_id: Signal<String>,
    recipient: Signal<String>,
    network_epoch: Signal<u64>,
    view_generation: Signal<u64>,
    expected_wallet: &str,
    expected_chain: &str,
    expected_recipient: &str,
    expected_network_epoch: u64,
    expected_view_generation: u64,
    operation_generation: &OperationGeneration,
    expected_operation_generation: u64,
) -> bool {
    wallet()
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case(expected_wallet))
        && chain_id().eq_ignore_ascii_case(expected_chain)
        && recipient().trim() == expected_recipient
        && network_epoch() == expected_network_epoch
        && view_generation() == expected_view_generation
        && operation_generation.load(Ordering::SeqCst) == expected_operation_generation
}

#[component]
pub fn SepoliaTransferPanel(
    wallet: Signal<Option<String>>,
    chain_id: Signal<String>,
    mut recipient: Signal<String>,
    language: Signal<String>,
    network_epoch: Signal<u64>,
    operation_generation: OperationGeneration,
) -> Element {
    let english = language() == "en";
    let mut amount = use_signal(String::new);
    let mut transfer_state = use_signal(|| TransferState::Idle);
    let mut transaction_hash = use_signal(|| None::<String>);
    let mut detail = use_signal(String::new);
    let mut context_notice = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut view_generation = use_signal(|| 0_u64);
    let mut observed_context = use_signal(|| None::<TransferContext>);

    // A changed wallet, recipient, chain, or parent network epoch clears the
    // rendered transfer state. It never claims that a previously submitted
    // transaction was canceled: a pending transaction can still exist on-chain.
    let effect_wallet = wallet;
    let effect_chain_id = chain_id;
    let effect_recipient = recipient;
    let effect_network_epoch = network_epoch;
    let mut effect_view_generation = view_generation;
    let mut effect_observed_context = observed_context;
    let mut effect_transfer_state = transfer_state;
    let mut effect_transaction_hash = transaction_hash;
    let mut effect_detail = detail;
    let mut effect_context_notice = context_notice;
    let mut effect_busy = busy;
    use_effect(move || {
        let context = TransferContext {
            wallet: effect_wallet().map(|value| value.to_ascii_lowercase()),
            recipient: effect_recipient().trim().to_string(),
            chain_id: effect_chain_id(),
            network_epoch: effect_network_epoch(),
        };
        let previous = effect_observed_context.read().clone();
        if previous.as_ref() != Some(&context) {
            let had_submitted_operation = matches!(
                effect_transfer_state.read().clone(),
                TransferState::Requesting | TransferState::Pending
            );
            let had_hash = effect_transaction_hash.read().is_some();
            effect_observed_context.set(Some(context));
            effect_view_generation.set(effect_view_generation().wrapping_add(1));
            effect_transfer_state.set(TransferState::Idle);
            effect_transaction_hash.set(None);
            effect_detail.set(String::new());
            effect_busy.set(false);
            effect_context_notice.set(if had_submitted_operation || had_hash {
                text(
                    language() == "en",
                    "The wallet or recipient changed. This view was reset; a submitted transaction may still be pending on Sepolia and was not canceled by NODO.",
                    "La wallet o el destinatario cambiaron. Esta vista se reinició; una transacción enviada aún puede estar pendiente en Sepolia y NODO no la canceló.",
                )
                .to_string()
            } else {
                String::new()
            });
        }
    });

    let wallet_value = wallet();
    let chain_value = chain_id();
    let recipient_value = recipient();
    let amount_value = amount();
    let state_value = transfer_state();
    let hash_value = transaction_hash();
    let connected = wallet_value.is_some();
    let on_sepolia = wallet_bridge::is_sepolia_chain_id(&chain_value);
    let visible_detail = detail();
    let visible_context_notice = context_notice();

    let review_click = {
        let mut amount = amount;
        let mut transfer_state = transfer_state;
        let mut detail = detail;
        let mut context_notice = context_notice;
        let wallet = wallet;
        let chain_id = chain_id;
        let recipient = recipient;
        move |_| match validate_form(
            english,
            &recipient(),
            &amount(),
            wallet().as_deref(),
            &chain_id(),
        ) {
            Ok(normalized) => {
                amount.set(normalized);
                detail.set(String::new());
                context_notice.set(String::new());
                transfer_state.set(TransferState::Review);
            }
            Err(error) => {
                detail.set(error);
                transfer_state.set(TransferState::Error);
            }
        }
    };

    let cancel_review = {
        let mut transfer_state = transfer_state;
        let mut detail = detail;
        move |_| {
            transfer_state.set(TransferState::Idle);
            detail.set(String::new());
        }
    };

    let confirm_click = {
        let wallet_signal = wallet;
        let chain_signal = chain_id;
        let recipient_signal = recipient;
        let network_epoch_signal = network_epoch;
        let view_generation_signal = view_generation;
        let generation = operation_generation.clone();
        let mut busy = busy;
        let mut transfer_state = transfer_state;
        let mut transaction_hash = transaction_hash;
        let mut detail = detail;
        move |_| {
            let Some(expected_wallet) = wallet_signal() else {
                detail.set(
                    text(
                        english,
                        "Connect a wallet first.",
                        "Conecta una wallet primero.",
                    )
                    .to_string(),
                );
                transfer_state.set(TransferState::Error);
                return;
            };
            let expected_recipient = recipient_signal().trim().to_string();
            let expected_chain = chain_signal();
            let expected_network_epoch = network_epoch_signal();
            let expected_view_generation = view_generation_signal();
            let expected_operation_generation = generation.load(Ordering::SeqCst);
            let normalized_amount = match validate_form(
                english,
                &expected_recipient,
                &amount(),
                Some(&expected_wallet),
                &expected_chain,
            ) {
                Ok(value) => value,
                Err(error) => {
                    detail.set(error);
                    transfer_state.set(TransferState::Error);
                    return;
                }
            };
            if !transfer_operation_is_current(
                wallet_signal,
                chain_signal,
                recipient_signal,
                network_epoch_signal,
                view_generation_signal,
                &expected_wallet,
                &expected_chain,
                &expected_recipient,
                expected_network_epoch,
                expected_view_generation,
                &generation,
                expected_operation_generation,
            ) {
                return;
            }

            busy.set(true);
            detail.set(String::new());
            transfer_state.set(TransferState::Requesting);
            let generation_for_task = generation.clone();
            let mut busy_for_task = busy;
            let mut transfer_state_for_task = transfer_state;
            let mut transaction_hash_for_task = transaction_hash;
            let mut detail_for_task = detail;
            spawn(async move {
                let submitted = wallet_bridge::send_native_transfer(
                    &expected_recipient,
                    &normalized_amount,
                    &expected_wallet,
                )
                .await;
                if !transfer_operation_is_current(
                    wallet_signal,
                    chain_signal,
                    recipient_signal,
                    network_epoch_signal,
                    view_generation_signal,
                    &expected_wallet,
                    &expected_chain,
                    &expected_recipient,
                    expected_network_epoch,
                    expected_view_generation,
                    &generation_for_task,
                    expected_operation_generation,
                ) {
                    return;
                }
                match submitted {
                    Ok(hash) => {
                        transaction_hash_for_task.set(Some(hash.clone()));
                        transfer_state_for_task.set(TransferState::Pending);
                        detail_for_task.set(text(
                            english,
                            "Transaction submitted; checking its Sepolia receipt without sending again…",
                            "Transacción enviada; comprobando su receipt de Sepolia sin volver a enviarla…",
                        ).to_string());
                        let receipt = wallet_bridge::wait_for_native_transfer_receipt(&hash).await;
                        if !transfer_operation_is_current(
                            wallet_signal,
                            chain_signal,
                            recipient_signal,
                            network_epoch_signal,
                            view_generation_signal,
                            &expected_wallet,
                            &expected_chain,
                            &expected_recipient,
                            expected_network_epoch,
                            expected_view_generation,
                            &generation_for_task,
                            expected_operation_generation,
                        ) {
                            return;
                        }
                        match receipt {
                            Ok(status) if status == "confirmed" => {
                                transfer_state_for_task.set(TransferState::Confirmed);
                                detail_for_task.set(
                                    text(
                                        english,
                                        "The Sepolia receipt is confirmed.",
                                        "El receipt de Sepolia está confirmado.",
                                    )
                                    .to_string(),
                                );
                            }
                            Ok(status) if status == "reverted" => {
                                transfer_state_for_task.set(TransferState::Reverted);
                                detail_for_task.set(
                                    text(
                                        english,
                                        "The transaction reverted. NODO did not retry it.",
                                        "La transacción fue revertida. NODO no la reintentó.",
                                    )
                                    .to_string(),
                                );
                            }
                            Ok(_) => {
                                transfer_state_for_task.set(TransferState::Pending);
                                detail_for_task.set(text(
                                    english,
                                    "No receipt yet; the submitted transaction remains pending. Refresh to check again.",
                                    "Aún no hay receipt; la transacción enviada sigue pendiente. Actualiza para comprobar de nuevo.",
                                ).to_string());
                            }
                            Err(error) => {
                                transfer_state_for_task.set(TransferState::Error);
                                detail_for_task.set(format!(
                                    "{} {}",
                                    text(
                                        english,
                                        "The transaction hash was returned, but its receipt could not be read. It may still be pending; use Refresh.",
                                        "Se devolvió el hash, pero no se pudo leer su receipt. Puede seguir pendiente; usa Actualizar.",
                                    ),
                                    localized_bridge_error(&error, english),
                                ));
                            }
                        }
                    }
                    Err(error) => {
                        transfer_state_for_task.set(TransferState::Error);
                        detail_for_task.set(localized_bridge_error(&error, english));
                    }
                }
                busy_for_task.set(false);
            });
        }
    };

    let refresh_click = {
        let wallet_signal = wallet;
        let chain_signal = chain_id;
        let recipient_signal = recipient;
        let network_epoch_signal = network_epoch;
        let view_generation_signal = view_generation;
        let generation = operation_generation.clone();
        let mut busy = busy;
        let mut transfer_state = transfer_state;
        let mut detail = detail;
        move |_| {
            let Some(hash) = transaction_hash() else {
                return;
            };
            let Some(expected_wallet) = wallet_signal() else {
                return;
            };
            let expected_recipient = recipient_signal().trim().to_string();
            let expected_chain = chain_signal();
            let expected_network_epoch = network_epoch_signal();
            let expected_view_generation = view_generation_signal();
            let expected_operation_generation = generation.load(Ordering::SeqCst);
            if !transfer_operation_is_current(
                wallet_signal,
                chain_signal,
                recipient_signal,
                network_epoch_signal,
                view_generation_signal,
                &expected_wallet,
                &expected_chain,
                &expected_recipient,
                expected_network_epoch,
                expected_view_generation,
                &generation,
                expected_operation_generation,
            ) {
                return;
            }
            busy.set(true);
            let generation_for_task = generation.clone();
            let mut busy_for_task = busy;
            let mut transfer_state_for_task = transfer_state;
            let mut detail_for_task = detail;
            spawn(async move {
                let receipt = wallet_bridge::read_native_transfer_receipt(&hash).await;
                if !transfer_operation_is_current(
                    wallet_signal,
                    chain_signal,
                    recipient_signal,
                    network_epoch_signal,
                    view_generation_signal,
                    &expected_wallet,
                    &expected_chain,
                    &expected_recipient,
                    expected_network_epoch,
                    expected_view_generation,
                    &generation_for_task,
                    expected_operation_generation,
                ) {
                    return;
                }
                match receipt {
                    Ok(status) if status == "confirmed" => {
                        transfer_state_for_task.set(TransferState::Confirmed);
                        detail_for_task.set(
                            text(
                                english,
                                "The Sepolia receipt is confirmed.",
                                "El receipt de Sepolia está confirmado.",
                            )
                            .to_string(),
                        );
                    }
                    Ok(status) if status == "reverted" => {
                        transfer_state_for_task.set(TransferState::Reverted);
                        detail_for_task.set(
                            text(
                                english,
                                "The transaction reverted. NODO did not retry it.",
                                "La transacción fue revertida. NODO no la reintentó.",
                            )
                            .to_string(),
                        );
                    }
                    Ok(_) => {
                        transfer_state_for_task.set(TransferState::Pending);
                        detail_for_task.set(
                            text(
                                english,
                                "The transaction is still pending; no send was retried.",
                                "La transacción sigue pendiente; no se reintentó el envío.",
                            )
                            .to_string(),
                        );
                    }
                    Err(error) => {
                        transfer_state_for_task.set(TransferState::Error);
                        detail_for_task.set(localized_bridge_error(&error, english));
                    }
                }
                busy_for_task.set(false);
            });
        }
    };

    rsx! {
        section { class: "secure-chat-card sepolia-transfer-card sepolia-transfer-panel", id: "sepolia-transfer",
            span { class: "section-kicker", if english { "OPTIONAL NATIVE TRANSFER · SEPOLIA" } else { "TRANSFERENCIA NATIVA OPCIONAL · SEPOLIA" } }
            h3 { if english { "Send test ETH to this peer" } else { "Enviar ETH de prueba a este peer" } }
            p { class: "sepolia-transfer-intro", if english { "This is independent of private chat, MessageBoard and anchoring. Selecting a conversation, sending a message, receiving a message, refreshing, or changing language never sends a transaction." } else { "Esto es independiente del chat privado, MessageBoard y el anclaje. Seleccionar una conversación, enviar o recibir un mensaje, actualizar o cambiar el idioma nunca envía una transacción." } }

            label { class: "field-label", if english { "RECIPIENT · EDIT ONLY IF YOU CHOOSE" } else { "DESTINATARIO · EDITA SOLO SI LO DECIDES" } }
            input {
                class: "text-field sepolia-transfer-recipient",
                r#type: "text",
                disabled: busy(),
                value: recipient_value,
                placeholder: "0x…",
                spellcheck: "false",
                autocomplete: "off",
                aria_label: if english { "Sepolia ETH recipient" } else { "Destinatario de ETH en Sepolia" },
                oninput: move |event| recipient.set(event.value()),
            }
            p { class: "sepolia-transfer-note", if english { "The field starts with the shared selected chat peer. NODO does not replace it automatically; editing it here is an explicit user choice." } else { "El campo comienza con el peer seleccionado en el chat. NODO no lo cambia automáticamente; editarlo aquí es una decisión explícita." } }

            label { class: "field-label", if english { "AMOUNT · ETH · EXACT DECIMAL, MAX 18 PLACES" } else { "IMPORTE · ETH · DECIMAL EXACTO, MÁX. 18 LUGARES" } }
            input {
                class: "text-field sepolia-transfer-amount",
                r#type: "text",
                disabled: busy(),
                inputmode: "decimal",
                value: amount_value,
                placeholder: if english { "0.001" } else { "0.001" },
                autocomplete: "off",
                spellcheck: "false",
                aria_label: if english { "Exact Sepolia ETH amount" } else { "Importe exacto de ETH en Sepolia" },
                oninput: move |event| amount.set(event.value()),
            }

            div { class: "sepolia-transfer-actions",
                button {
                    class: "button button-primary",
                    disabled: busy() || !connected || !on_sepolia,
                    onclick: review_click,
                    if busy() {
                        if english { "Working…" } else { "Procesando…" }
                    } else {
                        if english { "Review transfer" } else { "Revisar transferencia" }
                    }
                }
            }

            if state_value == TransferState::Review {
                div { class: "sepolia-transfer-review", role: "alert",
                    strong { if english { "Review before MetaMask" } else { "Revisa antes de MetaMask" } }
                    p { if english { "You are about to request a native ETH transfer on the public Ethereum Sepolia chain." } else { "Vas a solicitar una transferencia nativa de ETH en la cadena pública Ethereum Sepolia." } }
                    dl { class: "sepolia-transfer-summary",
                        div { dt { if english { "Recipient" } else { "Destinatario" } } dd { code { "{recipient_value}" } } }
                        div { dt { if english { "Amount" } else { "Importe" } } dd { code { "{amount_value} ETH" } } }
                        div { dt { if english { "From" } else { "Desde" } } dd { code { "{wallet_value.as_deref().map(short_address).unwrap_or_default()}" } } }
                    }
                    p { class: "sepolia-transfer-public-warning", if english { "Public-chain warning: sender, recipient, amount, timing and transaction status can be visible permanently. Only confirm if you accept that exposure and have checked the recipient and amount." } else { "Advertencia de cadena pública: emisor, destinatario, importe, hora y estado de la transacción pueden quedar visibles para siempre. Confirma solo si aceptas esa exposición y revisaste destinatario e importe." } }
                    div { class: "sepolia-transfer-review-actions",
                        button { class: "button button-quiet", disabled: busy(), onclick: cancel_review, if english { "Cancel" } else { "Cancelar" } }
                        button { class: "button button-primary", disabled: busy(), onclick: confirm_click, if english { "Confirm and request MetaMask ↗" } else { "Confirmar y solicitar MetaMask ↗" } }
                    }
                }
            }

            if state_value == TransferState::Requesting {
                div { class: "sepolia-transfer-status pending", role: "status", if english { "Waiting for your explicit MetaMask approval…" } else { "Esperando tu aprobación explícita en MetaMask…" } }
            }
            if state_value == TransferState::Pending || state_value == TransferState::Confirmed || state_value == TransferState::Reverted || state_value == TransferState::Error {
                div { class: "sepolia-transfer-status", role: "status",
                    strong {
                        if state_value == TransferState::Pending {
                            if english { "Pending" } else { "Pendiente" }
                        } else if state_value == TransferState::Confirmed {
                            if english { "Confirmed" } else { "Confirmada" }
                        } else if state_value == TransferState::Reverted {
                            if english { "Reverted" } else { "Revertida" }
                        } else {
                            if english { "Error" } else { "Error" }
                        }
                    }
                    if !visible_detail.is_empty() { span { " {visible_detail}" } }
                }
            }
            if !visible_context_notice.is_empty() {
                p { class: "sepolia-transfer-context-note", "{visible_context_notice}" }
            }
            if !visible_detail.is_empty() && state_value == TransferState::Error {
                p { class: "sepolia-transfer-error", "{visible_detail}" }
            }

            if let Some(hash) = hash_value.as_ref() {
                div { class: "sepolia-transfer-receipt",
                    span { class: "field-label", if english { "TRANSACTION HASH" } else { "HASH DE TRANSACCIÓN" } }
                    code { class: "sepolia-transfer-hash", "{hash}" }
                    div { class: "sepolia-transfer-receipt-actions",
                        a { class: "button button-quiet", href: "https://sepolia.etherscan.io/tx/{hash}", target: "_blank", rel: "noreferrer", if english { "View on Sepolia Etherscan ↗" } else { "Ver en Sepolia Etherscan ↗" } }
                        if state_value == TransferState::Pending || state_value == TransferState::Error {
                            button {
                                class: "button button-quiet",
                                disabled: busy(),
                                onclick: refresh_click,
                                if busy() {
                                    if english { "Checking…" } else { "Comprobando…" }
                                } else {
                                    if english { "Refresh receipt" } else { "Actualizar receipt" }
                                }
                            }
                        }
                    }
                }
            }

            if !connected {
                p { class: "sepolia-transfer-note", if english { "Connect MetaMask to request a Sepolia transfer. NODO never requests a private key or seed phrase." } else { "Conecta MetaMask para solicitar una transferencia en Sepolia. NODO nunca solicita una clave privada ni una frase semilla." } }
            } else if !on_sepolia {
                p { class: "sepolia-transfer-error", if english { "Transfers are disabled until the active wallet is on Ethereum Sepolia (chainId 11155111)." } else { "Las transferencias están desactivadas hasta que la wallet activa esté en Ethereum Sepolia (chainId 11155111)." } }
            }
            p { class: "sepolia-transfer-disclosure", if english { "Testnet only. NODO submits at most the one transaction you explicitly confirm. Receipt reads are read-only, bounded, and never retry the send." } else { "Solo testnet. NODO envía como máximo la única transacción que confirmas explícitamente. Las lecturas del receipt son de solo lectura, acotadas y nunca reintentan el envío." } }
        }
    }
}
