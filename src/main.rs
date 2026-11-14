mod relay_client;
mod secure_chat;
mod secure_chat_ui;
mod secure_messaging;
mod secure_storage;
mod sepolia_transfer_ui;
mod wallet_bridge;

use crate::secure_messaging::OperationGeneration;
use dioxus::prelude::*;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::sync::atomic::Ordering;
use wallet_bridge::ChainMessage;

const APP_CSS: Asset = asset!("/assets/main.css");
const APP_LOGO: Asset = asset!("/assets/logo.svg");
#[cfg(target_arch = "wasm32")]
const LANGUAGE_STORAGE_KEY: &str = "nodo.language.v1";

#[derive(Clone, Debug, PartialEq)]
struct MessageCard {
    id: String,
    sender: String,
    sender_name: String,
    recipient: String,
    content: String,
    received: String,
    status: String,
    content_hash: String,
    local_fingerprint: String,
    tx_hash: Option<String>,
    amount: String,
    is_demo: bool,
    is_read: bool,
    is_outgoing: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
struct SavedContact {
    name: String,
    address: String,
}

#[cfg(target_arch = "wasm32")]
const CONTACTS_STORAGE_KEY: &str = "nodo.contacts.v1";

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let language = use_signal(load_language);
    let english = language() == "en";
    let mut account = use_signal(|| None::<String>);
    let mut chain_id = use_signal(String::new);
    let wallet_locally_disconnected = use_signal(|| false);
    let wallet_epoch = use_signal(|| 0_u64);
    let operation_generation = use_hook(|| OperationGeneration::new(0));
    let wallet_busy = use_signal(|| false);
    let loading = use_signal(|| false);
    let mut notice = use_signal(String::new);
    let mut notice_kind = use_signal(|| String::from("info"));
    let messages = use_signal(demo_messages);
    let mut selected = use_signal(|| 0_usize);
    let mut composing = use_signal(|| false);
    let mut search = use_signal(String::new);
    let mut recipient = use_signal(String::new);
    let mut selected_peer = use_signal(String::new);
    let saved_peer_wallets = use_signal(Vec::<String>::new);
    let mut saved_contacts = use_signal(load_saved_contacts);
    let mut new_contact_name = use_signal(String::new);
    let mut contract_address = use_signal(String::new);
    let mut show_contract_settings = use_signal(|| false);
    let mut show_wallet_prompt = use_signal(|| true);

    #[cfg(target_arch = "wasm32")]
    {
        let generation = operation_generation.clone();
        use_hook(move || {
            install_wallet_listener(
                account,
                chain_id,
                wallet_locally_disconnected,
                wallet_epoch,
                messages,
                selected,
                loading,
                wallet_busy,
                generation,
            )
        });
    }

    let account_value = account();
    let connected = account_value.is_some();
    let short_account = account_value
        .as_deref()
        .map(short_address)
        .unwrap_or_default();
    let current_chain = chain_id();
    let is_sepolia = current_chain.eq_ignore_ascii_case("0xaa36a7");
    let contract_value = contract_address();
    let contract_format_valid = is_address(&contract_value);
    let all_messages = messages.read().clone();
    let selected_index = selected();
    let active_message = all_messages.get(selected_index).cloned();
    let query = search().to_lowercase();
    let visible_messages: Vec<(usize, MessageCard)> = all_messages
        .iter()
        .cloned()
        .enumerate()
        .filter(|(_, item)| {
            query.is_empty()
                || item.sender_name.to_lowercase().contains(&query)
                || item.sender.to_lowercase().contains(&query)
                || item.content.to_lowercase().contains(&query)
                || item.content_hash.to_lowercase().contains(&query)
        })
        .collect();
    let saved_contacts_list = saved_contacts.read().clone();
    let secure_contacts: Vec<(String, String)> = saved_contacts_list
        .iter()
        .map(|contact| (contact.name.clone(), contact.address.clone()))
        .collect();
    let private_conversations: Vec<(String, String)> = saved_peer_wallets
        .read()
        .iter()
        .filter(|address| {
            query.is_empty()
                || address.to_lowercase().contains(&query)
                || saved_contacts_list.iter().any(|contact| {
                    contact.address.eq_ignore_ascii_case(address)
                        && contact.name.to_lowercase().contains(&query)
                })
        })
        .map(|address| {
            let name = saved_contacts_list
                .iter()
                .find(|contact| contact.address.eq_ignore_ascii_case(address))
                .map(|contact| contact.name.clone())
                .unwrap_or_else(|| short_address(address));
            (name, address.clone())
        })
        .collect();
    let recipient_has_saved_contact = saved_contacts_list
        .iter()
        .any(|contact| contact.address.eq_ignore_ascii_case(&recipient()));
    let unread = all_messages
        .iter()
        .filter(|item| !item.is_outgoing && !item.is_read)
        .count();
    let notice_text = notice();
    let notice_style = if notice_kind() == "error" {
        "toast error"
    } else {
        "toast"
    };
    let chain_label = if !connected {
        if english {
            "Disconnected"
        } else {
            "Sin conexión"
        }
        .to_string()
    } else if is_sepolia {
        "Sepolia · testnet".to_string()
    } else {
        if english {
            format!("Network {}", current_chain)
        } else {
            format!("Red {}", current_chain)
        }
    };

    let connect_generation = operation_generation.clone();
    let connect_click = move |_| {
        request_wallet_connection(
            account,
            chain_id,
            wallet_locally_disconnected,
            wallet_epoch,
            connect_generation.clone(),
            wallet_busy,
            messages,
            selected,
            loading,
            notice,
            notice_kind,
            show_wallet_prompt,
        );
    };
    let connect_generation_mobile = operation_generation.clone();
    let connect_click_mobile = move |_| {
        request_wallet_connection(
            account,
            chain_id,
            wallet_locally_disconnected,
            wallet_epoch,
            connect_generation_mobile.clone(),
            wallet_busy,
            messages,
            selected,
            loading,
            notice,
            notice_kind,
            show_wallet_prompt,
        );
    };

    let disconnect_generation = operation_generation.clone();
    let disconnect_click = move |_| {
        let mut wallet_epoch = wallet_epoch;
        let mut wallet_locally_disconnected = wallet_locally_disconnected;
        let mut messages = messages;
        let mut selected = selected;
        let mut loading = loading;
        let mut wallet_busy = wallet_busy;
        disconnect_generation.fetch_add(1, Ordering::SeqCst);
        wallet_epoch.set(wallet_epoch().wrapping_add(1));
        wallet_locally_disconnected.set(true);
        account.set(None);
        chain_id.set(String::new());
        messages.set(Vec::new());
        selected.set(0);
        loading.set(false);
        wallet_busy.set(false);
        notice.set(
            "Wallet desconectada de esta interfaz. Para revocar permisos, revisa MetaMask."
                .to_string(),
        );
        notice_kind.set(String::from("info"));
    };

    let switch_generation = operation_generation.clone();
    let switch_chain_click = move |_| {
        let switch_generation = switch_generation.clone();
        let mut account = account;
        let mut chain_id = chain_id;
        let wallet_locally_disconnected = wallet_locally_disconnected;
        let mut wallet_epoch = wallet_epoch;
        let mut wallet_busy = wallet_busy;
        let mut messages = messages;
        let mut selected = selected;
        let mut loading = loading;
        let attempt = wallet_epoch().wrapping_add(1);
        wallet_epoch.set(attempt);
        wallet_busy.set(false);
        let mut notice = notice;
        let mut notice_kind = notice_kind;
        spawn(async move {
            let result = wallet_bridge::switch_to_sepolia().await;
            if wallet_locally_disconnected() || wallet_epoch() != attempt {
                return;
            }
            match result {
                Ok(snapshot) => {
                    let account_changed = account() != snapshot.account;
                    if account_changed || chain_id() != snapshot.chain_id {
                        if account_changed {
                            switch_generation.fetch_add(1, Ordering::SeqCst);
                        }
                        wallet_epoch.set(wallet_epoch().wrapping_add(1));
                        messages.set(Vec::new());
                        selected.set(0);
                        loading.set(false);
                    }
                    account.set(snapshot.account);
                    chain_id.set(snapshot.chain_id);
                    notice.set(
                        "Red cambiada a Ethereum Sepolia. Usa solo tokens de prueba.".to_string(),
                    );
                    notice_kind.set(String::from("info"));
                }
                Err(error) => {
                    notice.set(error);
                    notice_kind.set(String::from("error"));
                }
            }
        });
    };

    let refresh_click = move |_| {
        let mut loading = loading;
        let mut messages = messages;
        let mut notice = notice;
        let mut notice_kind = notice_kind;
        let contract = contract_address();
        let owner = account();
        let contract_signal = contract_address;
        let account_signal = account;
        let chain_signal = chain_id;
        let epoch_signal = wallet_epoch;
        let operation_epoch = epoch_signal();
        let expected_chain = chain_signal();
        spawn(async move {
            if epoch_signal() != operation_epoch {
                return;
            }
            if !is_address(&contract) {
                notice.set(
                    "Pega la dirección 0x… del contrato MessageBoard desplegado en Sepolia; no uses la URL RPC ni la dirección de tu wallet."
                        .to_string(),
                );
                notice_kind.set(String::from("error"));
                return;
            }
            let Some(owner) = owner else {
                notice.set(
                    "Conecta MetaMask para consultar el historial asociado a tu cuenta."
                        .to_string(),
                );
                notice_kind.set(String::from("error"));
                return;
            };
            loading.set(true);
            let result = wallet_bridge::load_inbox(&contract, &owner).await;
            if epoch_signal() != operation_epoch
                || account_signal().as_deref() != Some(owner.as_str())
                || chain_signal() != expected_chain
                || contract_signal() != contract
            {
                loading.set(false);
                return;
            }
            match result {
                Ok(records) => {
                    messages.set(
                        records
                            .into_iter()
                            .map(|record| from_chain_record(record, &owner))
                            .collect(),
                    );
                    notice.set("Historial cargado desde el contrato.".to_string());
                    notice_kind.set(String::from("info"));
                }
                Err(error) => {
                    notice.set(error);
                    notice_kind.set(String::from("error"));
                }
            }
            loading.set(false);
        });
    };

    let save_contact_click = move |_| {
        let name = new_contact_name().trim().to_string();
        let address = recipient().trim().to_string();
        if name.is_empty() || name.chars().count() > 60 {
            notice.set("Escribe un nombre de contacto de 1 a 60 caracteres.".to_string());
            notice_kind.set(String::from("error"));
            return;
        }
        if !is_address(&address) {
            notice.set(
                "Escribe primero una dirección EVM válida (0x + 40 caracteres hexadecimales)."
                    .to_string(),
            );
            notice_kind.set(String::from("error"));
            return;
        }
        let mut next = saved_contacts.read().clone();
        if let Some(existing) = next
            .iter_mut()
            .find(|contact| contact.address.eq_ignore_ascii_case(&address))
        {
            existing.name = name;
        } else if next.len() >= 200 {
            notice.set("La agenda local llegó al límite de 200 contactos.".to_string());
            notice_kind.set(String::from("error"));
            return;
        } else {
            next.push(SavedContact { name, address });
        }
        next.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        match persist_saved_contacts(&next) {
            Ok(()) => {
                saved_contacts.set(next);
                new_contact_name.set(String::new());
                notice.set("Contacto guardado en este navegador. Puedes seleccionarlo en tus próximos mensajes.".to_string());
                notice_kind.set(String::from("info"));
            }
            Err(error) => {
                notice.set(error);
                notice_kind.set(String::from("error"));
            }
        }
    };

    let remove_contact_click = move |_| {
        let address = recipient().trim().to_string();
        let mut next = saved_contacts.read().clone();
        let previous_len = next.len();
        next.retain(|contact| !contact.address.eq_ignore_ascii_case(&address));
        if next.len() == previous_len {
            return;
        }
        match persist_saved_contacts(&next) {
            Ok(()) => {
                saved_contacts.set(next);
                recipient.set(String::new());
                notice.set("Contacto eliminado de la agenda local.".to_string());
                notice_kind.set(String::from("info"));
            }
            Err(error) => {
                notice.set(error);
                notice_kind.set(String::from("error"));
            }
        }
    };

    rsx! {
        document::Title { if english { "NODO — Verifiable messaging" } else { "NODO — Mensajería verificable" } }
        document::Meta { name: "theme-color", content: "#17152b" }
        document::Meta { name: "description", content: if english { "Web3 messaging with verifiable hashes and wallet control." } else { "Mensajería Web3 con hashes verificables y control desde tu wallet." } }
        document::Link { rel: "icon", href: APP_LOGO }
        document::Link { rel: "stylesheet", href: APP_CSS }
        main { class: "app-shell", lang: if english { "en" } else { "es" },
            header { class: "topbar",
                a { class: "brand", href: "#inicio", aria_label: "NODO, inicio",
                    img { class: "brand-icon", src: APP_LOGO, alt: "" }
                    span { class: "brand-copy", strong { "nodo" } small { if english { "VERIFIABLE MESSAGING" } else { "MENSAJERÍA VERIFICABLE" } } }
                }
                nav { class: "main-nav", aria_label: if english { "Main navigation" } else { "Navegación principal" },
                    a { href: "#mensajeria-segura", class: "nav-link active", if english { "Private chat" } else { "Chat privado" } }
                    a { href: "#bandeja", class: "nav-link", if english { "Sepolia records" } else { "Registros Sepolia" } }
                    a { href: "#protocolo", class: "nav-link", if english { "Protocol" } else { "Protocolo" } }
                    a { href: "#privacidad", class: "nav-link", if english { "Privacy" } else { "Privacidad" } }
                }
                div { class: "topbar-actions",
                    button { class: "button button-quiet language-toggle", title: if english { "Switch to Spanish" } else { "Switch to English" }, aria_label: if english { "Switch language to Spanish" } else { "Cambiar idioma a inglés" }, onclick: move |_| toggle_language(language), if english { "EN" } else { "ES" } }
                    div { class: "network-pill", span { class: if connected && is_sepolia { "status-dot online" } else { "status-dot" } }, if connected { "{chain_label}" } else { "EVM · demo" } }
                    if connected {
                        div { class: "wallet-connected",
                            span { class: "wallet-avatar", "{short_account.chars().take(2).collect::<String>()}" }
                            span { class: "wallet-address", "{short_account}" }
                            button { class: "icon-button", title: if english { "Disconnect from this interface" } else { "Desconectar de esta interfaz" }, aria_label: if english { "Disconnect wallet" } else { "Desconectar wallet" }, onclick: disconnect_click, "×" }
                        }
                    } else {
                        button { class: "button button-connect", disabled: wallet_busy(), onclick: connect_click,
                            span { class: "button-glyph", "↗" }
                            if wallet_busy() { if english { "Connecting…" } else { "Conectando…" } } else { if english { "Connect wallet" } else { "Conectar wallet" } }
                        }
                    }
                }
            }

            if show_wallet_prompt() && !connected {
                section { class: "wallet-prompt", role: "region", aria_label: if english { "Choose wallet connection or demo mode" } else { "Elegir conexión de wallet o modo demo" },
                    div { class: "wallet-prompt-copy",
                        strong { if english { "Would you like to connect MetaMask?" } else { "¿Quieres conectar MetaMask?" } }
                        p { if english { "Connect to use Sepolia and sign transactions, or continue in demo mode without changing the blockchain." } else { "Conecta para usar Sepolia y firmar transacciones; o continúa en modo demo sin modificar la blockchain." } }
                    }
                    div { class: "wallet-prompt-actions",
                        button { class: "button button-connect", disabled: wallet_busy(), onclick: connect_click_mobile, if wallet_busy() { if english { "Connecting…" } else { "Conectando…" } } else { if english { "Connect wallet" } else { "Conectar wallet" } } }
                        button { class: "button button-quiet", onclick: move |_| { show_wallet_prompt.set(false); notice.set(if english { "Demo mode is active. No on-chain writes will be made.".to_string() } else { "Modo demo activo. No se harán escrituras on-chain.".to_string() }); notice_kind.set(String::from("info")); }, if english { "Continue in demo" } else { "Continuar en demo" } }
                    }
                }
            }

            section { id: "inicio", class: "intro-row",
                div { class: "intro-copy",
                    div { class: "eyebrow", span { class: "eyebrow-line" } span { if english { "MESSAGES WITH PROOF, NOT PROMISES" } else { "MENSAJES CON PRUEBA, NO CON PROMESAS" } } }
                    h1 { if english { "Your message. " } else { "Tu mensaje. " } span { class: "headline-accent", if english { "Your signature." } else { "Tu firma." } } }
                    p { class: "intro-text", if english { "Send messages tied to your wallet and verify their record on a public network. Sensitive content stays off-chain." } else { "Envía mensajes vinculados a tu wallet y verifica su registro en una red pública. El contenido sensible permanece fuera de la cadena." } }
                }
                div { class: "intro-aside",
                    div { class: "privacy-stamp", span { class: "stamp-icon", "◉" }, span { strong { if english { "Privacy by design" } else { "Privacidad por diseño" } } small { if english { "On-chain: hash and minimal metadata" } else { "On-chain: hash y metadatos mínimos" } } } }
                    div { class: "orbit orbit-one" } div { class: "orbit orbit-two" }
                }
            }

            if !notice_text.is_empty() {
                div { class: notice_style, role: "status",
                    span { class: "toast-mark", if notice_kind() == "error" { "!" } else { "i" } }
                    span { "{localized_notice(&notice_text, english)}" }
                    button { class: "toast-close", aria_label: if english { "Close notice" } else { "Cerrar aviso" }, onclick: move |_| notice.set(String::new()), "×" }
                }
            }

            nav { class: "chat-entry-nav", aria_label: if english { "Messaging sections" } else { "Secciones de mensajería" },
                a { class: "button button-primary", href: "#mensajeria-segura", if english { "Private chat · text + UTC times" } else { "Chat privado · texto + horas UTC" } }
                a { class: "button button-quiet", href: "#bandeja", if english { "View public records" } else { "Ver registros públicos" } }
                span { class: "frontend-revision", "NODO CHAT · 2026.10.22.4" }
            }

            secure_chat_ui::SecureChatPanel {
                wallet: account,
                chain_id,
                contacts: secure_contacts,
                contract_address,
                network_epoch: wallet_epoch,
                language,
                operation_generation: operation_generation.clone(),
                selected_peer,
                saved_peer_wallets,
            }

            sepolia_transfer_ui::SepoliaTransferPanel {
                wallet: account,
                chain_id,
                recipient: selected_peer,
                language,
                network_epoch: wallet_epoch,
                operation_generation: operation_generation.clone(),
            }

            div { class: "chain-history-heading",
                h2 { if english { "Public Sepolia records" } else { "Registros públicos de Sepolia" } }
                p { if english { "This history contains hashes and blockchain dates, not private message bodies or delivery receipts. Read and send messages in the private chat above." } else { "Este historial contiene hashes y fechas de la blockchain, no el texto privado ni recibos de entrega. Lee y envía mensajes en el chat privado de arriba." } }
            }

            section { id: "bandeja", class: "workspace",
                aside { class: "inbox-panel",
                    div { class: "panel-heading", div { span { class: "section-kicker", if english { "ON-CHAIN HISTORY" } else { "HISTORIAL ON-CHAIN" } } h2 { if english { "Records" } else { "Registros" } } }, span { class: "count-badge", "{unread}" } }
                    label { class: "search-box", span { class: "search-icon", "⌕" }, input { r#type: "search", placeholder: if english { "Search messages" } else { "Buscar mensajes" }, value: search(), oninput: move |event| search.set(event.value()), aria_label: if english { "Search messages" } else { "Buscar mensajes" } }, kbd { "⌘ K" } }
                    div { class: "private-conversation-index",
                        span { class: "section-kicker", if english { "PRIVATE CONVERSATIONS · LOCAL" } else { "CONVERSACIONES PRIVADAS · LOCALES" } }
                        if private_conversations.is_empty() {
                            p { class: "secure-chat-note", if english { "Unlock your profile to load saved chats. Older message bodies are deleted after 72 hours." } else { "Desbloquea tu perfil para cargar los chats guardados. Los mensajes se eliminan tras 72 horas." } }
                        }
                        for (name, address) in private_conversations.clone() {
                            a { key: "{address}", href: "#mensajeria-segura", class: if selected_peer().eq_ignore_ascii_case(&address) { "private-conversation-row selected" } else { "private-conversation-row" }, onclick: move |_| selected_peer.set(address.clone()),
                                strong { "{name}" }
                                span { if english { "Open private history ↗" } else { "Abrir historial privado ↗" } }
                            }
                        }
                    }
                    div { class: "inbox-label-row", span { if english { "RECENT" } else { "RECIENTES" } }, span { class: "live-label", span { class: "live-dot" }, if connected { "WALLET" } else { if english { "DEMO" } else { "DEMO" } } } }
                    div { class: "message-list",
                        if visible_messages.is_empty() { div { class: "empty-list", if english { "No messages match your search." } else { "No hay mensajes que coincidan con la búsqueda." } } }
                        for (index, item) in visible_messages.clone() {
                            button { class: if index == selected_index && !composing() { "message-row selected" } else { "message-row" }, onclick: move |_| { selected.set(index); composing.set(false); notice.set(String::new()); },
                                div { class: "row-avatar", "{initials(&item.sender_name)}" }
                                div { class: "row-content",
                                    div { class: "row-title-line", strong { "{localized_sender_name(&item.sender_name, english)}" }, time { "{localized_received(&item.received, english)}" } }
                                p { "{preview_text(&item.content, &item.content_hash, english)}" }
                                    div { class: "row-meta", span { class: if item.is_demo { "record-chip demo-chip" } else { "record-chip" }, if item.is_demo { if english { "LOCAL DEMO" } else { "DEMO LOCAL" } } else { if english { "RECORD" } else { "REGISTRO" } } }, if !item.is_outgoing && !item.is_read { span { class: "unread-dot" } } }
                                }
                            }
                        }
                    }
                    button { class: "button button-new", onclick: move |_| { composing.set(true); notice.set(String::new()); }, span { class: "plus-icon", "+" }, if english { "Manage contacts" } else { "Gestionar contactos" } }
                    div { class: "inbox-footnote", span { class: "footnote-glyph", "⌁" }, if english { "MetaMask signs the binding; E2EE keys are encrypted locally." } else { "MetaMask firma el vínculo; las claves E2EE se cifran localmente." } }
                }

                section { class: "conversation-panel",
                    div { class: "conversation-topline",
                        div { class: "conversation-context", span { class: "section-kicker", if composing() { if english { "LOCAL CONTACTS" } else { "AGENDA LOCAL" } } else { if english { "PAST RECORDS" } else { "REGISTROS ANTERIORES" } } },
                            if composing() { h2 { if english { "Saved contacts" } else { "Contactos guardados" } } } else if let Some(item) = active_message.as_ref() { h2 { "{localized_sender_name(&item.sender_name, english)}" } } else { h2 { if english { "Your inbox" } else { "Tu bandeja" } } }
                        }
                        div { class: "conversation-tools",
                            span { class: if connected { "secure-state live" } else { "secure-state" }, span { class: "state-pulse" }, if connected { if english { "Wallet active" } else { "Wallet activa" } } else { if english { "Read only" } else { "Solo lectura" } } }
                            button { class: "icon-button refresh-button", title: if english { "Refresh from contract" } else { "Actualizar desde el contrato" }, aria_label: if english { "Refresh history" } else { "Actualizar historial" }, disabled: loading(), onclick: refresh_click, if loading() { "…" } else { "↻" } }
                        }
                    }
                    if composing() {
                        div { class: "composer-view",
                            div { class: "compose-intro", span { class: "compose-spark", "✳" }, div { h3 { if english { "Your contacts stay in this browser." } else { "La agenda se queda en tu navegador." } } p { if english { "New messages use end-to-end encrypted chat. Publicly sending text hashes is disabled." } else { "Los mensajes nuevos usan el chat cifrado de extremo a extremo. El envío público de hashes de texto se desactivó." } } } }
                            div { class: "contact-book",
                                div { class: "contact-book-heading", label { class: "field-label", if english { "SAVED CONTACTS · THIS BROWSER" } else { "CONTACTOS GUARDADOS · ESTE NAVEGADOR" } }, span { class: "contact-count", "{saved_contacts_list.len()}" } }
                                select { class: "text-field contact-select", value: recipient(), onchange: move |event| recipient.set(event.value()), aria_label: if english { "Select a saved contact" } else { "Seleccionar un contacto guardado" },
                                    option { value: "", if english { "Select a saved contact…" } else { "Selecciona un contacto guardado…" } }
                                    for contact in saved_contacts_list.clone() {
                                        option { value: "{contact.address}", "{contact.name} · {short_address(&contact.address)}" }
                                    }
                                }
                                p { class: "contact-book-note", if english { "MetaMask does not share its private address book with DApps. This list stays in this browser." } else { "MetaMask no comparte su agenda privada con las DApps. Esta lista se guarda solo en este navegador." } }
                                label { class: "field-label contact-name-label", if english { "NAME TO SAVE OR RENAME" } else { "NOMBRE PARA GUARDAR O RENOMBRAR" } }
                                div { class: "contact-save-row",
                                    input { class: "text-field contact-name-field", r#type: "text", placeholder: if english { "For example, Alex" } else { "Por ejemplo, Alex" }, value: new_contact_name(), maxlength: "60", oninput: move |event| new_contact_name.set(event.value()), aria_label: if english { "Contact name to save" } else { "Nombre para guardar el contacto" } }
                                    button { class: "button button-quiet contact-save-button", onclick: save_contact_click, disabled: new_contact_name().trim().is_empty() || !is_address(&recipient()), if english { "Save contact" } else { "Guardar contacto" } }
                                }
                                if recipient_has_saved_contact {
                                    button { class: "contact-remove-button", onclick: remove_contact_click, if english { "Remove selected contact" } else { "Eliminar contacto seleccionado" } }
                                }
                            }
                            label { class: "field-label", if english { "CONTACT EVM ADDRESS" } else { "DIRECCIÓN EVM DEL CONTACTO" } }
                            input { class: "text-field address-field", r#type: "text", placeholder: "0x…", value: recipient(), oninput: move |event| recipient.set(event.value()), spellcheck: "false", autocomplete: "off", aria_label: if english { "Recipient EVM address" } else { "Dirección EVM del destinatario" } }
                            div { class: "composer-warning", span { "i" }, span { if english { "Saving or renaming a contact does not create transactions or publish the address on-chain." } else { "Guardar o renombrar un contacto no crea transacciones ni publica la dirección en la cadena." } } }
                            div { class: "composer-actions", button { class: "button button-quiet", onclick: move |_| composing.set(false), if english { "Close" } else { "Cerrar" } }, a { class: "button button-primary", href: "#mensajeria-segura", onclick: move |_| { if is_address(&recipient()) { selected_peer.set(recipient()); } }, if english { "Open this contact's chat ↑" } else { "Abrir chat de este contacto ↑" } } }
                        }
                    } else if let Some(item) = active_message.as_ref() {
                        div { class: "conversation-body",
                            div { class: "message-date-divider", span {}, "{localized_received(&item.received, english)}", span {} }
                            div { class: if item.is_demo || !item.is_outgoing { "bubble-wrap incoming" } else { "bubble-wrap outgoing" },
                                div { class: "bubble-avatar", "{initials(&item.sender_name)}" }
                                div { class: "message-bubble",
                                    div { class: "bubble-header", strong { "{localized_sender_name(&item.sender_name, english)}" }, span { "{short_address(&item.sender)}" } }
                                    if item.content.is_empty() { p { class: "message-text muted-message", if english { "This on-chain record stores only a hash and cannot recover the message body. To show readable text on both devices, send it through private E2EE chat." } else { "Este registro on-chain guarda solo un hash y no puede recuperar el cuerpo. Para mostrar texto legible en ambos dispositivos, envíalo por el chat privado E2EE." } } } else { p { class: "message-text", "{item.content}" } }
                                    div { class: "bubble-footer", span { class: if item.is_demo { "record-chip demo-chip" } else { "record-chip" }, if item.is_demo { if english { "LOCAL · NOT PUBLISHED" } else { "LOCAL · NO PUBLICADO" } } else { if english { "ON-CHAIN PROOF" } else { "HUELLA ON-CHAIN" } } }, if item.amount != "0 ETH" { span { class: "amount-chip", "↗ {item.amount}" } } }
                                }
                            }
                            div { class: "proof-card",
                                div { class: "proof-heading", div { class: "proof-icon", "⌘" }, div { strong { if english { "Integrity proof" } else { "Prueba de integridad" } } p { if english { "The record does not reveal the message text." } else { "El registro no revela el texto del mensaje." } } }, span { class: if item.status == "CONFIRMADA" { "proof-state confirmed" } else if item.status == "PENDIENTE" { "proof-state pending" } else { "proof-state" }, "{localized_record_status(&item.status, english)}" } }
                                div { class: "hash-row", span { if english { "KECCAK-256 · RECORD" } else { "KECCAK-256 · REGISTRO" } }, code { "{short_hash(&item.content_hash)}" }, button { class: "copy-button", title: if english { "Copy hash" } else { "Copiar hash" }, onclick: { let hash = item.content_hash.clone(); move |_| copy_to_clipboard(&hash) }, if english { "Copy" } else { "Copiar" } } }
                                if !item.local_fingerprint.is_empty() { div { class: "hash-row local-hash", span { if english { "SHA-256 · LOCAL FINGERPRINT" } else { "SHA-256 · HUELLA LOCAL" } }, code { "{short_hash(&item.local_fingerprint)}" }, span { class: "local-only-label", if english { "THIS SESSION ONLY" } else { "SOLO ESTA SESIÓN" } } } }
                                if let Some(tx_hash) = item.tx_hash.as_ref() { a { class: "explorer-link", href: "https://sepolia.etherscan.io/tx/{tx_hash}", target: "_blank", rel: "noreferrer", if english { "View on Sepolia Etherscan ↗" } else { "Ver en Sepolia Etherscan ↗" } } }
                                if item.content.is_empty() && !item.is_demo { a { class: "e2ee-record-link", href: "#mensajeria-segura", onclick: { let peer = if item.is_outgoing { item.recipient.clone() } else { item.sender.clone() }; move |_| { if is_address(&peer) { selected_peer.set(peer.clone()); } } }, if english { "Open this peer's private history ↑" } else { "Abrir historial privado de esta wallet ↑" } } }
                            }
                            if item.is_demo { div { class: "demo-notice", span { "i" }, p { strong { if english { "Local preview." } else { "Muestra local." } } if english { " No transaction exists for this record. Real messages are sent from encrypted chat." } else { " No existe una transacción para este registro. Los mensajes reales se envían desde el chat cifrado." } } } }
                        }
                    } else {
                        div { class: "empty-conversation", div { class: "empty-orbit", "⌁" }, h3 { if english { "No records yet" } else { "Todavía no hay registros" } }, p { if english { "Past on-chain records appear here. To send new messages, use end-to-end encrypted chat." } else { "Aquí aparecen los registros on-chain anteriores. Para enviar mensajes nuevos, usa el chat cifrado de extremo a extremo." } } }
                    }
                }

                aside { class: "context-panel",
                    div { class: "context-card network-card",
                        span { class: "section-kicker", if english { "NETWORK STATUS" } else { "ESTADO DE RED" } }
                        div { class: "network-head", div { class: "ethereum-mark", "◈" }, div { strong { if is_sepolia { "Ethereum Sepolia" } else if connected { if english { "Unverified network" } else { "Red no verificada" } } else { if english { "No wallet" } else { "Sin wallet" } } }, small { if connected { "EVM · chain {current_chain}" } else { if english { "Connect to choose a network" } else { "Conecta para elegir tu red" } } } } }
                        div { class: "network-rule" }
                        div { class: "network-stats", div { span { if english { "Mode" } else { "Modo" } } strong { if connected { "WALLET" } else { "DEMO" } } }, div { span { if english { "Contract" } else { "Contrato" } } strong { if contract_format_valid { if english { "0x FORMAT OK" } else { "FORMATO 0x OK" } } else { if english { "NOT SET" } else { "SIN CONFIGURAR" } } } } }
                        if connected && !is_sepolia { button { class: "button button-chain", onclick: switch_chain_click, if english { "Switch to Sepolia" } else { "Cambiar a Sepolia" } } }
                        button { class: "text-action", onclick: move |_| show_contract_settings.set(!show_contract_settings()), if show_contract_settings() { if english { "Hide settings −" } else { "Ocultar configuración −" } } else { if english { "Configure contract +" } else { "Configurar contrato +" } } }
                        if show_contract_settings() { label { class: "contract-label", if english { "SEPOLIA CONTRACT ADDRESS" } else { "DIRECCIÓN DEL CONTRATO EN SEPOLIA" } }, input { class: "contract-input", r#type: "text", placeholder: "0x…", value: contract_value, oninput: move |event| contract_address.set(event.value()), spellcheck: "false", autocomplete: "off", aria_label: if english { "Deployed contract address on Sepolia" } else { "Dirección del contrato desplegado en Sepolia" } }, p { class: "contract-help", if english { "Paste the 0x… address of the deployed MessageBoard. This is not an RPC URL or wallet address. NODO checks for bytecode on Sepolia; this form does not deploy the contract." } else { "Pega la dirección 0x… de MessageBoard desplegado. No es la URL RPC ni la dirección de una wallet. NODO comprobará que haya bytecode en Sepolia; este formulario no publica el contrato." } } }
                    }
                    div { class: "context-card safety-card", id: "privacidad", span { class: "section-kicker", if english { "CLEAR AND VERIFIABLE" } else { "CLARO Y VERIFICABLE" } }, h3 { if english { "The chain is not private." } else { "La cadena no es privada." } }, p { if english { "Addresses, hashes, amounts and timestamps may be public. NODO never writes message bodies on-chain." } else { "Direcciones, hashes, importes y tiempos pueden ser públicos. NODO no escribe el cuerpo del mensaje on-chain." } }, a { href: "#protocolo", class: "inline-link", if english { "How it works ↗" } else { "Cómo funciona ↗" } } }
                    div { class: "context-card crypto-card", div { class: "crypto-header", div { class: "crypto-sigil", "✳" }, div { span { class: "section-kicker", if english { "CRYPTOGRAPHIC LAYER" } else { "CAPA CRIPTOGRÁFICA" } } strong { "Olm · Rust · WASM" } } }, p { if english { "Your wallet only signs its binding to the E2EE identity. Messaging keys are encrypted locally; the relay receives ciphertext." } else { "La wallet solo firma su vínculo con la identidad E2EE. Las claves de mensajería se cifran localmente; el relay recibe ciphertext." } }, span { class: "crypto-footnote", if english { "RANDOM IVs · RATCHET" } else { "IVs ALEATORIOS · RATCHET" } } }
                }
            }

            section { id: "protocolo", class: "protocol-strip",
                div { class: "protocol-title", span { class: "section-kicker", if english { "BUILT FOR THE WEB" } else { "DISEÑADO PARA LA WEB" } }, h2 { if english { "Lightweight proof. " } else { "Una prueba ligera. " } span { class: "headline-accent", if english { "Your choice." } else { "Una decisión tuya." } } }, p { if english { "NODO links wallet identity and on-chain evidence without pretending a public message is private." } else { "NODO enlaza identidad wallet y evidencia on-chain sin fingir que un mensaje público es privado." } } }
                div { class: "protocol-steps",
                    article { class: "protocol-step", span { class: "step-number", "01" }, div { class: "step-symbol", "⌘" }, h3 { if english { "Encrypt" } else { "Cifra" } }, p { if english { "Olm Triple-DH and Double Ratchet encrypt every message on your device." } else { "Olm Triple-DH y Double Ratchet cifran cada mensaje en tu dispositivo." } } }
                    article { class: "protocol-step", span { class: "step-number", "02" }, div { class: "step-symbol", "∿" }, h3 { if english { "Verify" } else { "Verifica" } }, p { if english { "Compare the wallet–key fingerprint; the relay only transports ciphertext." } else { "Compara la huella wallet–clave; el relay solo transporta ciphertext." } } }
                    article { class: "protocol-step", span { class: "step-number", "03" }, div { class: "step-symbol", "↗" }, h3 { if english { "Anchor (optional)" } else { "Ancla (opcional)" } }, p { if english { "MetaMask can record the random hash of the encrypted envelope; regular delivery needs no gas." } else { "MetaMask puede registrar el hash aleatorio del sobre cifrado; un envío normal no requiere gas." } } }
                }
            }
            footer { class: "footer", a { class: "brand footer-brand", href: "#inicio", img { class: "brand-icon small-brand-icon", src: APP_LOGO, alt: "" }, strong { "nodo" } }, p { if english { "Verifiable messaging · EVM · Rust" } else { "Mensajería verificable · EVM · Rust" } }, span { class: "footer-disclaimer", if english { "TESTNET · DO NOT SEND REAL FUNDS" } else { "TESTNET · NO ENVÍES FONDOS REALES" } } }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn load_saved_contacts() -> Vec<SavedContact> {
    let serialized = web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item(CONTACTS_STORAGE_KEY).ok().flatten());
    let mut contacts = serialized
        .and_then(|value| serde_json::from_str::<Vec<SavedContact>>(&value).ok())
        .unwrap_or_default();
    contacts.retain(|contact| !contact.name.trim().is_empty() && is_address(&contact.address));
    contacts.truncate(200);
    contacts
}

#[cfg(not(target_arch = "wasm32"))]
fn load_saved_contacts() -> Vec<SavedContact> {
    Vec::new()
}

fn persist_saved_contacts(contacts: &[SavedContact]) -> Result<(), String> {
    let serialized = serde_json::to_string(contacts)
        .map_err(|_| "No se pudieron preparar los contactos para guardarlos.".to_string())?;
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()
            .ok_or_else(|| "No se pudo acceder al almacenamiento del navegador.".to_string())?;
        let storage = window
            .local_storage()
            .map_err(|_| "El navegador bloqueó el almacenamiento local.".to_string())?
            .ok_or_else(|| {
                "El almacenamiento local no está disponible en este navegador.".to_string()
            })?;
        storage
            .set_item(CONTACTS_STORAGE_KEY, &serialized)
            .map_err(|_| "No se pudieron guardar los contactos. Comprueba el espacio y los permisos del navegador.".to_string())?;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = serialized;
    }
    Ok(())
}

fn demo_messages() -> Vec<MessageCard> {
    let samples = [
        ("Marina R.", "0x73a1c52bb2290c7f2a119b20", "La propuesta ya está lista para revisión. Te paso el enlace en cuanto quede publicada.", "Hoy · 10:42", "0.001 ETH"),
        ("Equipo Nodo", "0x8b910a72b8c8f3d9b173e09e", "La huella de la versión anterior coincide con el acta. Registro verificado.", "Ayer · 18:07", "0 ETH"),
        ("Gabriel T.", "0x41fbd8a2f32139c06ca2270b", "¿Puedes confirmar que recibiste el borrador? El texto completo no se escribe en la cadena.", "14 oct · 09:16", "0 ETH"),
    ];
    samples
        .into_iter()
        .enumerate()
        .map(
            |(index, (name, sender, content, received, amount))| MessageCard {
                id: format!("demo-{index}"),
                sender: sender.to_string(),
                sender_name: name.to_string(),
                recipient: "Tú · demo".to_string(),
                content: content.to_string(),
                received: received.to_string(),
                status: "DEMO LOCAL".to_string(),
                content_hash: keccak_hex(content),
                local_fingerprint: sha256_hex(content),
                tx_hash: None,
                amount: amount.to_string(),
                is_demo: true,
                is_read: index != 0,
                is_outgoing: false,
            },
        )
        .collect()
}

fn from_chain_record(record: ChainMessage, account: &str) -> MessageCard {
    let is_outgoing = record.sender.eq_ignore_ascii_case(account);
    MessageCard {
        id: record.id,
        sender_name: if is_outgoing {
            "Tú".to_string()
        } else {
            short_address(&record.sender)
        },
        sender: record.sender,
        recipient: record.recipient,
        content: String::new(),
        received: format!("Registro · {}", format_chain_timestamp(&record.created_at)),
        status: if record.cancelled {
            "CANCELADO".to_string()
        } else if record.is_read {
            "LEÍDO".to_string()
        } else if is_outgoing {
            "ENVIADO".to_string()
        } else {
            "RECIBIDO".to_string()
        },
        content_hash: record.content_hash.clone(),
        local_fingerprint: String::new(),
        tx_hash: None,
        amount: format!("{} ETH", record.amount),
        is_demo: false,
        is_read: record.is_read,
        is_outgoing,
    }
}

fn keccak_hex(value: &str) -> String {
    let result = Keccak256::digest(value.as_bytes());
    format!(
        "0x{}",
        result
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
fn sha256_hex(value: &str) -> String {
    let result = digest(&SHA256, value.as_bytes());
    format!(
        "0x{}",
        result
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
fn is_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}
fn short_address(value: &str) -> String {
    if !value.starts_with("0x") || value.len() <= 13 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..6], &value[value.len() - 4..])
    }
}
fn short_hash(value: &str) -> String {
    if value.len() <= 30 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..12], &value[value.len() - 8..])
    }
}
fn initials(value: &str) -> String {
    let result: String = value
        .split_whitespace()
        .filter_map(|word| word.chars().next())
        .take(2)
        .collect();
    if result.is_empty() {
        "N".to_string()
    } else {
        result.to_uppercase()
    }
}
fn preview_text(content: &str, hash: &str, english: bool) -> String {
    if content.is_empty() {
        format!(
            "{} {}",
            if english { "Fingerprint" } else { "Huella" },
            short_hash(hash)
        )
    } else {
        content.chars().take(64).collect()
    }
}

fn copy_to_clipboard(value: &str) {
    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window() {
        let _ = window.navigator().clipboard().write_text(value);
    }
    let _ = value;
}

fn request_wallet_connection(
    account: Signal<Option<String>>,
    chain_id: Signal<String>,
    wallet_locally_disconnected: Signal<bool>,
    wallet_epoch: Signal<u64>,
    generation: OperationGeneration,
    wallet_busy: Signal<bool>,
    messages: Signal<Vec<MessageCard>>,
    selected: Signal<usize>,
    loading: Signal<bool>,
    notice: Signal<String>,
    notice_kind: Signal<String>,
    show_wallet_prompt: Signal<bool>,
) {
    if wallet_busy() {
        return;
    }
    let mut wallet_busy = wallet_busy;
    let mut notice = notice;
    let mut wallet_epoch_start = wallet_epoch;
    let attempt = wallet_epoch().wrapping_add(1);
    generation.fetch_add(1, Ordering::SeqCst);
    wallet_epoch_start.set(attempt);
    wallet_busy.set(true);
    notice.set(String::new());
    let connection = wallet_bridge::connect();

    let mut account = account;
    let mut chain_id = chain_id;
    let mut wallet_locally_disconnected = wallet_locally_disconnected;
    let mut wallet_epoch = wallet_epoch;
    let mut messages = messages;
    let mut selected = selected;
    let mut loading = loading;
    let mut notice = notice;
    let mut notice_kind = notice_kind;
    let mut show_wallet_prompt = show_wallet_prompt;
    spawn(async move {
        let result = connection.await;
        if wallet_epoch() == attempt {
            match result {
                Ok(snapshot) => {
                    let account_changed = account() != snapshot.account;
                    if account_changed || chain_id() != snapshot.chain_id {
                        if account_changed {
                            generation.fetch_add(1, Ordering::SeqCst);
                        }
                        wallet_epoch.set(wallet_epoch().wrapping_add(1));
                        messages.set(Vec::new());
                        selected.set(0);
                        loading.set(false);
                    }
                    wallet_locally_disconnected.set(false);
                    show_wallet_prompt.set(false);
                    account.set(snapshot.account.clone());
                    chain_id.set(snapshot.chain_id.clone());
                    notice.set(if snapshot.chain_id.eq_ignore_ascii_case("0xaa36a7") {
                        "Wallet conectada en Sepolia. Para escribir necesitas configurar un contrato.".to_string()
                    } else {
                        format!("Wallet conectada. Cambia a Sepolia para probar esta DApp. Red actual: {}", snapshot.chain_id)
                    });
                    notice_kind.set(String::from("info"));
                }
                Err(error) => {
                    notice.set(error);
                    notice_kind.set(String::from("error"));
                }
            }
            wallet_busy.set(false);
        }
    });
}

#[cfg(target_arch = "wasm32")]
fn install_wallet_listener(
    mut account: Signal<Option<String>>,
    mut chain_id: Signal<String>,
    wallet_locally_disconnected: Signal<bool>,
    mut wallet_epoch: Signal<u64>,
    mut messages: Signal<Vec<MessageCard>>,
    mut selected: Signal<usize>,
    mut loading: Signal<bool>,
    mut wallet_busy: Signal<bool>,
    generation: OperationGeneration,
) {
    use wasm_bindgen::{closure::Closure, JsCast};
    let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        if wallet_locally_disconnected() {
            return;
        }
        let Some(event) = event.dyn_ref::<web_sys::CustomEvent>() else {
            return;
        };
        let Some(detail) = event.detail().as_string() else {
            return;
        };
        if let Ok(snapshot) = serde_json::from_str::<wallet_bridge::WalletSnapshot>(&detail) {
            let next_account = snapshot.account.filter(|value| !value.trim().is_empty());
            let account_changed = account() != next_account;
            let chain_changed = chain_id() != snapshot.chain_id;
            if !account_changed && !chain_changed {
                return;
            }
            if account_changed {
                generation.fetch_add(1, Ordering::SeqCst);
            }
            wallet_epoch.set(wallet_epoch().wrapping_add(1));
            account.set(next_account);
            chain_id.set(snapshot.chain_id);
            messages.set(Vec::new());
            selected.set(0);
            loading.set(false);
            wallet_busy.set(false);
        }
    });
    if let Some(window) = web_sys::window() {
        let _ = window
            .add_event_listener_with_callback("nodo:wallet", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

#[cfg(target_arch = "wasm32")]
fn load_language() -> String {
    web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item(LANGUAGE_STORAGE_KEY).ok().flatten())
        .filter(|value| value == "en" || value == "es")
        .unwrap_or_else(|| "es".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn load_language() -> String {
    "es".to_string()
}

fn toggle_language(mut language: Signal<String>) {
    let selected = if language() == "en" { "es" } else { "en" };
    language.set(selected.to_string());
    #[cfg(target_arch = "wasm32")]
    if let Some(storage) =
        web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    {
        let _ = storage.set_item(LANGUAGE_STORAGE_KEY, selected);
    }
}

fn localized_sender_name(name: &str, english: bool) -> String {
    if english && name == "Tú" {
        "You".to_string()
    } else {
        name.to_string()
    }
}

fn localized_received(received: &str, english: bool) -> String {
    if english {
        received
            .strip_prefix("Registro · ")
            .map(|value| format!("Record · {value}"))
            .unwrap_or_else(|| received.to_string())
    } else {
        received.to_string()
    }
}

fn format_chain_timestamp(timestamp_seconds: &str) -> String {
    let Ok(seconds) = timestamp_seconds.parse::<i64>() else {
        return timestamp_seconds.to_string();
    };
    let Some(timestamp_ms) = seconds.checked_mul(1000) else {
        return timestamp_seconds.to_string();
    };
    if timestamp_ms <= 0 || timestamp_ms > 8_640_000_000_000_000 {
        return timestamp_seconds.to_string();
    }
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(timestamp_ms as f64))
            .to_iso_string()
            .as_string()
            .unwrap_or_else(|| timestamp_seconds.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        timestamp_seconds.to_string()
    }
}

fn localized_record_status(status: &str, english: bool) -> String {
    if !english {
        return status.to_string();
    }
    match status {
        "CONFIRMADA" => "CONFIRMED".to_string(),
        "PENDIENTE" => "PENDING".to_string(),
        "CANCELADO" => "CANCELED".to_string(),
        "LEÍDO" => "READ".to_string(),
        "ENVIADO" => "SENT".to_string(),
        "RECIBIDO" => "RECEIVED".to_string(),
        _ => status.to_string(),
    }
}

fn localized_notice(message: &str, english: bool) -> String {
    if !english {
        return message.to_string();
    }
    if let Some(network) = message
        .strip_prefix("Wallet conectada. Cambia a Sepolia para probar esta DApp. Red actual: ")
    {
        return format!(
            "Wallet connected. Switch to Sepolia to test this DApp. Current network: {network}"
        );
    }
    for (spanish, english) in [(
        "Respuesta de wallet inválida: ",
        "Invalid wallet response: ",
    )] {
        if let Some(detail) = message.strip_prefix(spanish) {
            return format!("{english}{detail}");
        }
    }
    match message {
        "Escribe primero una dirección EVM válida (0x + 40 caracteres hexadecimales)." => {
            "Enter a valid EVM address first (0x + 40 hexadecimal characters).".to_string()
        }
        "Escribe un nombre de contacto de 1 a 60 caracteres." => {
            "Enter a contact name between 1 and 60 characters.".to_string()
        }
        "La agenda local llegó al límite de 200 contactos." => {
            "The local address book has reached its limit of 200 contacts.".to_string()
        }
        "Contacto guardado en este navegador. Puedes seleccionarlo en tus próximos mensajes." => {
            "Contact saved in this browser. You can select it in future messages.".to_string()
        }
        "Contacto eliminado de la agenda local." => {
            "Contact removed from the local address book.".to_string()
        }
        "Historial cargado desde el contrato." => "History loaded from the contract.".to_string(),
        "Modo demo activo. No se harán escrituras on-chain." => {
            "Demo mode is active. No on-chain writes will be made.".to_string()
        }
        "Wallet desconectada de esta interfaz. Para revocar permisos, revisa MetaMask." => {
            "Wallet disconnected from this interface. To revoke permissions, review MetaMask.".to_string()
        }
        "Red cambiada a Ethereum Sepolia. Usa solo tokens de prueba." => {
            "Network switched to Ethereum Sepolia. Use test tokens only.".to_string()
        }
        "Wallet conectada en Sepolia. Para escribir necesitas configurar un contrato." => {
            "Wallet connected on Sepolia. Configure a contract to write records.".to_string()
        }
        "Pega la dirección 0x… del contrato MessageBoard desplegado en Sepolia; no uses la URL RPC ni la dirección de tu wallet." => {
            "Paste the 0x… address of the MessageBoard contract deployed on Sepolia; do not use the RPC URL or your wallet address.".to_string()
        }
        "Conecta MetaMask para consultar el historial asociado a tu cuenta." => {
            "Connect MetaMask to load the history associated with your account.".to_string()
        }
        "El navegador bloqueó el almacenamiento local." => {
            "The browser blocked local storage.".to_string()
        }
        "El almacenamiento local no está disponible en este navegador." => {
            "Local storage is unavailable in this browser.".to_string()
        }
        "No hay bytecode de contrato en esa dirección de Sepolia. Usa la dirección del MessageBoard desplegado, no la de una wallet ni una URL RPC." => {
            "No contract bytecode was found at that Sepolia address. Use the deployed MessageBoard contract address, not a wallet address or RPC URL.".to_string()
        }
        "No se recibió la cuenta que inició el anclaje." => {
            "The account that initiated the anchor was not received.".to_string()
        }
        "La cuenta activa de MetaMask cambió. Vuelve a seleccionar el mensaje con la wallet correcta." => {
            "The active MetaMask account changed. Select the message again with the correct wallet.".to_string()
        }
        "La wallet de la vinculación debe ser una dirección Ethereum válida." => {
            "The binding wallet must be a valid Ethereum address.".to_string()
        }
        "El deviceId de la vinculación debe ser texto." => {
            "The binding deviceId must be text.".to_string()
        }
        "identityKeyHash debe ser un bytes32 hexadecimal (0x + 64 dígitos)." => {
            "identityKeyHash must be a hexadecimal bytes32 value (0x + 64 digits).".to_string()
        }
        "El nonce de la vinculación debe ser texto." => {
            "The binding nonce must be text.".to_string()
        }
        "expiresAt debe ser un entero uint64 seguro; pásalo como texto si es grande." => {
            "expiresAt must be a safe uint64 integer; pass it as text if it is large.".to_string()
        }
        "MetaMask rechazó la firma EIP-712. La vinculación no fue aprobada." => {
            "MetaMask rejected the EIP-712 signature. The binding was not approved.".to_string()
        }
        "El proveedor no admite el método eth_signTypedData_v4 requerido para esta vinculación." => {
            "The provider does not support eth_signTypedData_v4, which this binding requires.".to_string()
        }
        "Ya hay una solicitud de MetaMask pendiente. Resuélvela antes de volver a firmar." => {
            "A MetaMask request is already pending. Resolve it before signing again.".to_string()
        }
        "La firma de vinculación requiere Ethereum Sepolia (chainId 11155111)." => {
            "The binding signature requires Ethereum Sepolia (chainId 11155111).".to_string()
        }
        "No hay una cuenta conectada para firmar la vinculación." => {
            "No account is connected to sign the binding.".to_string()
        }
        "MetaMask devolvió una firma EIP-712 inválida." => {
            "MetaMask returned an invalid EIP-712 signature.".to_string()
        }
        "MetaMask rechazó la conexión. Vuelve a intentarlo desde NODO y acepta la solicitud." => {
            "MetaMask rejected the connection. Try again from NODO and approve the request.".to_string()
        }
        "Ya hay una solicitud de MetaMask pendiente. Abre la extensión y resuélvela antes de volver a conectar." => {
            "A MetaMask request is already pending. Open the extension and resolve it before reconnecting.".to_string()
        }
        "El proveedor no admite el método solicitado por la wallet." => {
            "The provider does not support the wallet method that was requested.".to_string()
        }
        "La operación de wallet no se completó." => "The wallet operation did not complete.".to_string(),
        "MetaMask agotó el tiempo de conexión. Cierra cualquier solicitud pendiente, recarga NODO y pulsa «Conectar MetaMask» desde la página para aprobar el acceso." => {
            "The MetaMask connection timed out. Close any pending request, reload NODO, then click Connect MetaMask on the page to approve access.".to_string()
        }
        "Respuesta de wallet inválida." => "Invalid wallet response.".to_string(),
        "La conexión de wallet está disponible en el sitio web." => "Wallet connection is available on the website.".to_string(),
        "El cambio de red está disponible en el sitio web." => "Network switching is available on the website.".to_string(),
        "El envío on-chain está disponible en el sitio web." => "On-chain sending is available on the website.".to_string(),
        "La consulta de transacciones está disponible en el sitio web." => "Transaction lookup is available on the website.".to_string(),
        "La lectura del contrato está disponible en el sitio web." => "Contract reading is available on the website.".to_string(),
        "La firma EIP-712 de wallet está disponible en el sitio web." => "EIP-712 wallet signing is available on the website.".to_string(),
        "La recuperación de firmas EIP-712 está disponible en el sitio web." => "EIP-712 signature recovery is available on the website.".to_string(),
        "La verificación de firmas EIP-712 está disponible en el sitio web." => "EIP-712 signature verification is available on the website.".to_string(),
        "No se pudieron preparar los contactos para guardarlos." => {
            "Could not prepare contacts for saving.".to_string()
        }
        _ if looks_like_spanish_notice(message) => {
            "The operation could not be completed. Switch to Spanish to view the detailed diagnostic.".to_string()
        }
        _ => message.to_string(),
    }
}

fn looks_like_spanish_notice(message: &str) -> bool {
    message
        .chars()
        .any(|character| matches!(character, 'á' | 'é' | 'í' | 'ó' | 'ú' | 'ñ' | '¿' | '¡'))
        || [
            "El ",
            "La ",
            "No se ",
            "No hay ",
            "Escribe ",
            "Conecta ",
            "Desbloquea ",
            "Cambia ",
            "Pega ",
            "Wallet conectada",
            "Wallet desconectada",
            "Red cambiada",
            "Contacto ",
            "La agenda ",
        ]
        .iter()
        .any(|prefix| message.starts_with(prefix))
}

#[cfg(test)]
mod locale_tests {
    use super::*;

    #[test]
    fn english_mode_translates_wallet_and_network_notices() {
        assert_eq!(
            localized_notice(
                "Red cambiada a Ethereum Sepolia. Usa solo tokens de prueba.",
                true
            ),
            "Network switched to Ethereum Sepolia. Use test tokens only."
        );
        assert_eq!(
            localized_notice(
                "Wallet conectada. Cambia a Sepolia para probar esta DApp. Red actual: 0x1",
                true
            ),
            "Wallet connected. Switch to Sepolia to test this DApp. Current network: 0x1"
        );
    }

    #[test]
    fn unknown_spanish_wallet_notice_uses_an_english_fallback() {
        assert!(localized_notice("La wallet emitió un error nuevo.", true)
            .starts_with("The operation could not be completed."));
    }
}
