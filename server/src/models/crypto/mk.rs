use std::borrow::Cow;

use chrono::{DateTime, Duration, Utc};
use identifier::Identifier;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Mk<'a> {
    #[serde(skip_serializing_if = "Identifier::is_none")]
    id: Identifier,
    pub added_on: DateTime<Utc>,
    pub expires_on: DateTime<Utc>,
    pub is_active: bool,
    pub key: Cow<'a, [u8]>,
    #[serde(skip)]
    pub decoded_key: Option<SecretValue>,
}

impl<'a> Mk<'a> {
    pub fn new(key: Vec<u8>) -> Self {
        Mk {
            id: Identifier::default(),
            added_on: Utc::now(),
            expires_on: Utc::now() + Duration::days(90),
            is_active: true,
            key: key.into(),
            decoded_key: None,
        }
    }

    pub fn get_id(&self) -> &Identifier {
        &self.id
    }
}
