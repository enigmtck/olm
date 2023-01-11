#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::Curve25519PublicKey;
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

#[wasm_bindgen(getter_with_clone)]
#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct EnigmatickState {
    pickled_account: Option<String>,
    olm_sessions: Option<HashMap<String, String>>,
}

#[wasm_bindgen]
impl EnigmatickState {
    pub fn new() -> EnigmatickState {
        EnigmatickState::default()
    }

    pub fn set_pickled_account(&mut self, data: String) -> Self {
        self.pickled_account = Option::from(data);
        self.clone()
    }

    pub fn set_olm_sessions(&mut self, data: String) -> Self {
        self.olm_sessions =
            Option::from(serde_json::from_str::<HashMap<String, String>>(&data).unwrap());
        self.clone()
    }

    pub fn get_olm_sessions(&self) -> String {
        serde_json::to_string(&self.olm_sessions).unwrap()
    }

    pub fn set_olm_session(&mut self, ap_id: String, session: String) -> Self {
        if let Some(sessions) = self.olm_sessions.clone() {
            let mut sessions = sessions;
            sessions.insert(ap_id, session);
            self.olm_sessions = Option::from(sessions);
        }
        self.clone()
    }

    pub fn get_olm_session(&self, ap_id: String) -> Option<String> {
        if let Some(sessions) = &self.olm_sessions {
            sessions.get(&ap_id).cloned()
        } else {
            Option::None
        }
    }

    pub fn export(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

lazy_static! {
    pub static ref ENIGMATICK_STATE: Arc<Mutex<EnigmatickState>> =
        Arc::new(Mutex::new(EnigmatickState::new()));
}

#[wasm_bindgen]
pub fn get_state() -> EnigmatickState {
    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.lock() {
        x.clone()
    } else {
        EnigmatickState::default()
    }
}

#[wasm_bindgen]
pub fn import_state(data: String) {
    log(&format!("import olm: {}", data));

    let imported_state: EnigmatickState = match serde_json::from_str(&data) {
        Ok(x) => x,
        Err(e) => {
            log(&format!("{:#?}", e));
            EnigmatickState::default()
        }
    };

    log(&format!("imported_state: {:#?}", imported_state));
    let state = &*ENIGMATICK_STATE.clone();

    if let Ok(mut x) = state.try_lock() {
        x.set_pickled_account(imported_state.pickled_account.unwrap());
        x.set_olm_sessions(serde_json::to_string(&imported_state.olm_sessions.unwrap()).unwrap());
    };
}

#[wasm_bindgen]
pub fn export_account() -> Option<String> {
    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.try_lock() {
        x.pickled_account.clone()
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub fn create_olm_account() -> String {
    let account = Account::new();
    let pickled_account = serde_json::to_string(&account.pickle()).unwrap();

    let state = &*ENIGMATICK_STATE.clone();

    if let Ok(mut x) = state.try_lock() {
        x.set_pickled_account(pickled_account.clone());
    }

    pickled_account
}

#[wasm_bindgen]
pub fn create_olm_message(
    ap_id: String,
    message: String,
    identity_key: Option<String>,
    one_time_key: Option<String>,
) -> Option<String> {
    // Consider using olm_sessions map to check for existence of map to create message
    // that would probably make the _keys above Optional
    if let Ok(mut x) = (*ENIGMATICK_STATE).try_lock() {
        if let Some(session) = x.get_olm_session(ap_id.clone()) {
            let pickle: Option<SessionPickle> =
                match serde_json::from_str::<SessionPickle>(&session) {
                    Ok(x) => Option::from(x),
                    Err(e) => {
                        log(&format!("failed to deserialize session pickle: {:#?}", e));
                        Option::None
                    }
                };

            if let Some(pickle) = pickle {
                let mut session = Session::from_pickle(pickle);
                let message = serde_json::to_string(&session.encrypt(message)).unwrap();
                x.set_olm_session(ap_id, serde_json::to_string(&session.pickle()).unwrap());
                Option::from(message)
            } else {
                Option::None
            }
        } else if let (Some(pickle), Some(identity_key), Some(one_time_key)) =
            (&x.pickled_account, identity_key, one_time_key)
        {
            let one_time_key_bytes = base64::decode(one_time_key).unwrap();
            let one_time_key =
                Curve25519PublicKey::from_bytes(one_time_key_bytes.try_into().unwrap());
            let identity_key = Curve25519PublicKey::from_base64(&identity_key).unwrap();

            let account = Account::from(serde_json::from_str::<AccountPickle>(pickle).unwrap());

            let mut outbound = account.create_outbound_session(
                SessionConfig::version_2(),
                identity_key,
                one_time_key,
            );

            let message = serde_json::to_string(&outbound.encrypt(message)).unwrap();

            log(&format!(
                "setting pickled olm session: {:#?}",
                serde_json::to_string(&outbound.pickle()).unwrap()
            ));
            x.set_olm_session(ap_id, serde_json::to_string(&outbound.pickle()).unwrap());

            Option::from(message)
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub fn decrypt_olm_message(ap_id: String, message: String, identity_key: String) -> Option<String> {
    let state = &*ENIGMATICK_STATE;

    let identity_key = Curve25519PublicKey::from_base64(&identity_key).unwrap();

    if let Ok(mut x) = state.try_lock() {
        if let Some(pickle) = &x.pickled_account {
            let mut account = Account::from(serde_json::from_str::<AccountPickle>(pickle).unwrap());

            if let OlmMessage::PreKey(m) = serde_json::from_str(&message).unwrap() {
                let inbound = account.create_inbound_session(identity_key, &m);

                if let Ok(inbound) = inbound {
                    let session = serde_json::to_string(&inbound.session.pickle()).unwrap();
                    log(&format!("setting pickled olm session: {:#?}", session));
                    x.set_olm_session(ap_id, session);

                    Option::from(String::from_utf8(inbound.plaintext).unwrap())
                } else {
                    Option::None
                }
            } else {
                Option::None
            }
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub fn get_one_time_keys() -> Option<String> {
    let state = &*ENIGMATICK_STATE;

    if let Ok(mut x) = state.try_lock() {
        if let Some(pickle) = &x.pickled_account {
            let mut account = Account::from(serde_json::from_str::<AccountPickle>(pickle).unwrap());
            account.generate_one_time_keys(10);
            let one_time_keys = serde_json::to_string(&account.one_time_keys()).unwrap();
            account.mark_keys_as_published();
            x.pickled_account = Option::from(serde_json::to_string(&account.pickle()).unwrap());
            Option::from(one_time_keys)
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}

#[wasm_bindgen]
pub fn get_identity_public_key() -> Option<String> {
    let state = &*ENIGMATICK_STATE;

    if let Ok(x) = state.try_lock() {
        if let Some(pickle) = &x.pickled_account {
            let account = Account::from(serde_json::from_str::<AccountPickle>(pickle).unwrap());
            Option::from(account.curve25519_key().to_base64())
        } else {
            Option::None
        }
    } else {
        Option::None
    }
}
