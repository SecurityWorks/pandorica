use std::borrow::Cow;

use chrono::{DateTime, Utc};
use crypto::hashing::Argon2id;
use crypto::traits::HashingProvider;
use foreign::IntoKey;
use identifier::Identifier;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use shared::error::OperationResult;

#[derive(Serialize, Deserialize, Clone)]
pub struct Password<'a> {
    #[serde(skip_serializing_if = "Identifier::is_none")]
    id: Identifier,
    #[serde(skip)]
    pub plaintext: Option<SecretValue>,
    pub hash: Cow<'a, [u8]>,
    pub added_on: DateTime<Utc>,
    pub is_active: bool,
}

impl<'a> IntoKey for Password<'a> {
    fn get_key(&self) -> String {
        self.id.as_string()
    }
}

impl<'a> Password<'a> {
    pub fn new(plaintext: SecretValue) -> OperationResult<Self> {
        let hash = Argon2id::generate_hash_ns(&plaintext)?;

        Ok(Password {
            id: Identifier::default(),
            plaintext: Some(plaintext),
            hash: hash.into(),
            added_on: Utc::now(),
            is_active: true,
        })
    }

    pub fn get_id(&self) -> &Identifier {
        &self.id
    }

    pub fn verify(&self, other: &Password<'_>) -> OperationResult<bool> {
        self.plaintext
            .as_ref()
            .unwrap()
            .exposed_in_as_zvec(|p| Argon2id::verify_hash(p.as_slice(), &other.hash))
    }
}
