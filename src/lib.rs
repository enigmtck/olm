#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use vodozemac::olm::{Account, AccountPickle, SessionConfig};
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

    pub fn export(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

lazy_static! {
    pub static ref ENIGMATICK_STATE: Arc<Mutex<EnigmatickState>> =
        Arc::new(Mutex::new(EnigmatickState::new()));
}

#[wasm_bindgen]
pub async fn get_state() -> EnigmatickState {
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
    let imported_state: EnigmatickState = serde_json::from_str(&data).unwrap();

    log(&format!("imported_state: {:#?}", imported_state));
    let state = &*ENIGMATICK_STATE.clone();

    if let Ok(mut x) = state.try_lock() {
        x.set_pickled_account(imported_state.pickled_account.unwrap());
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
    message: String,
    identity_key: String,
    one_time_key: String,
) -> Option<String> {
    let state = &*ENIGMATICK_STATE.clone();

    let identity_key = Curve25519PublicKey::from_base64(&identity_key).unwrap();
    let one_time_key = Curve25519PublicKey::from_base64(&one_time_key).unwrap();

    let mut olm_message = Option::<String>::None;

    if let Ok(x) = state.try_lock() {
        if let Some(pickle) = &x.pickled_account {
            let account = Account::from(serde_json::from_str::<AccountPickle>(pickle).unwrap());

            let mut outbound = account.create_outbound_session(
                SessionConfig::version_2(),
                identity_key,
                one_time_key,
            );

            olm_message = Option::from(serde_json::to_string(&outbound.encrypt(message)).unwrap());
        }
    }

    olm_message
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
