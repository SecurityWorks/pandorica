use std::borrow::Cow;

use chrono::{DateTime, Utc};
use crypto::argon2id::Argon2id;
use foreign::IntoKey;
use identifier::Identifier;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use shared::error::OperationResult;

#[derive(Serialize, Deserialize, Clone)]
pub struct Password<'a> {
    #[serde(skip_serializing_if = "Identifier::is_none")]
    id: Identifier,
    pub user_id: Cow<'a, str>,
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
    pub fn new(plaintext: SecretValue, user_id: String) -> OperationResult<Self> {
        let hash = Argon2id::generate_hash(&plaintext)?;

        Ok(Password {
            id: Identifier::default(),
            user_id: user_id.into(),
            plaintext: Some(plaintext),
            hash: hash.into(),
            added_on: Utc::now(),
            is_active: true,
        })
    }

    pub fn get_id(&self) -> &Identifier {
        &self.id
    }

    pub fn verify(&self, hashed: &Password<'_>) -> OperationResult<bool> {
        Argon2id::verify_hash(self.plaintext.as_ref().unwrap(), &hashed.hash)
    }
}
