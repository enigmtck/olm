#![allow(non_upper_case_globals)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::{Curve25519PublicKey, KeyId};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn date_now() -> f64;
}

#[wasm_bindgen]
pub fn create_olm_account() -> String {
    let account = Account::new();
    serde_json::to_string(&account.pickle()).unwrap()
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize)]
pub struct MessageResponse {
    pub remote_actor: String,
    pub message: String,
    pub session: String,
}

#[wasm_bindgen]
pub fn create_olm_message(
    ap_id: String,
    message: String,
    pickled_account: String,
    identity_key: Option<String>,
    one_time_key: Option<String>,
    olm_session: Option<String>,
) -> Option<MessageResponse> {
    log(&format!(
        "in create_olm_message state\nchecking for\n{:#?}",
        ap_id
    ));
    if let Some(session) = olm_session {
        let pickle: Option<SessionPickle> = match serde_json::from_str::<SessionPickle>(&session) {
            Ok(x) => Option::from(x),
            Err(e) => {
                log(&format!("failed to deserialize session pickle: {:#?}", e));
                Option::None
            }
        };

        if let Some(pickle) = pickle {
            let mut session = Session::from_pickle(pickle);
            let message = serde_json::to_string(&session.encrypt(message)).unwrap();
            let remote_actor = ap_id;
            let session = serde_json::to_string(&session.pickle()).unwrap();
            Option::from(MessageResponse {
                remote_actor,
                message,
                session,
            })
        } else {
            Option::None
        }
    } else if let (Some(identity_key), Some(one_time_key)) = (identity_key, one_time_key) {
        // if there's no pre-existing session and keys are submitted, create a new session
        let one_time_key_bytes = base64::decode(one_time_key).unwrap();
        let one_time_key = Curve25519PublicKey::from_bytes(one_time_key_bytes.try_into().unwrap());
        let identity_key = Curve25519PublicKey::from_base64(&identity_key).unwrap();

        let account =
            Account::from(serde_json::from_str::<AccountPickle>(&pickled_account).unwrap());

        let mut outbound =
            account.create_outbound_session(SessionConfig::version_2(), identity_key, one_time_key);

        let message = serde_json::to_string(&outbound.encrypt(message)).unwrap();

        log(&format!(
            "setting pickled olm session: {:#?}",
            serde_json::to_string(&outbound.pickle()).unwrap()
        ));
        let remote_actor = ap_id;
        let session = serde_json::to_string(&outbound.pickle()).unwrap();

        Option::from(MessageResponse {
            remote_actor,
            message,
            session,
        })
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub fn decrypt_olm_message(
    ap_id: String,
    message: String,
    pickled_account: String,
    identity_key: String,
    olm_session: Option<String>,
) -> Option<MessageResponse> {
    let identity_key = Curve25519PublicKey::from_base64(&identity_key).unwrap();

    let mut account =
        Account::from(serde_json::from_str::<AccountPickle>(&pickled_account).unwrap());

    if let Some(session) = olm_session {
        let pickle: Option<SessionPickle> = match serde_json::from_str::<SessionPickle>(&session) {
            Ok(x) => Option::from(x),
            Err(e) => {
                log(&format!("failed to deserialize session pickle: {:#?}", e));
                Option::None
            }
        };

        if let Some(pickle) = pickle {
            let mut session = Session::from_pickle(pickle);

            if let OlmMessage::Normal(m) = serde_json::from_str(&message).unwrap() {
                match session.decrypt(&m.into()) {
                    Ok(bytes) => {
                        let message = String::from_utf8(bytes).unwrap();
                        let remote_actor = ap_id;
                        let session = serde_json::to_string(&session.pickle()).unwrap();
                        Option::from(MessageResponse {
                            remote_actor,
                            message,
                            session,
                        })
                    }
                    Err(e) => {
                        log(&format!("decryption error\n{:#?}", e));
                        Option::None
                    }
                }
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else if let OlmMessage::PreKey(m) = serde_json::from_str(&message).unwrap() {
        let inbound = account.create_inbound_session(identity_key, &m);

        if let Ok(inbound) = inbound {
            let session = serde_json::to_string(&inbound.session.pickle()).unwrap();
            let remote_actor = ap_id;
            let message = String::from_utf8(inbound.plaintext).unwrap();

            Option::from(MessageResponse {
                remote_actor,
                message,
                session,
            })
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Serialize, Deserialize)]
pub struct AccountResponse {
    pub one_time_keys: String,
    pub pickled_account: String,
}

#[wasm_bindgen]
pub fn get_one_time_keys(pickled_account: String) -> AccountResponse {
    let mut account =
        Account::from(serde_json::from_str::<AccountPickle>(&pickled_account).unwrap());
    account.generate_one_time_keys(2);
    let b64map: HashMap<KeyId, String> = account
        .one_time_keys()
        .into_iter()
        .map(|(k, v)| (k, v.to_base64()))
        .collect();

    let one_time_keys = serde_json::to_string(&b64map).unwrap();
    account.mark_keys_as_published();
    let pickled_account = serde_json::to_string(&account.pickle()).unwrap();
    AccountResponse {
        one_time_keys,
        pickled_account,
    }
}

#[wasm_bindgen]
pub fn get_identity_public_key(pickled_account: String) -> String {
    let account = Account::from(serde_json::from_str::<AccountPickle>(&pickled_account).unwrap());
    account.curve25519_key().to_base64()
}
