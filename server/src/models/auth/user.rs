use chrono::{DateTime, Utc};
use std::borrow::Cow;

use identifier::Identifier;
use protobuf::pandorica_common;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use shared::error::OperationResult;

use crate::models::crypto::EncryptedValue;

#[derive(Serialize, Deserialize, Clone)]
pub struct User<'a> {
    #[serde(skip_serializing_if = "Identifier::is_none")]
    id: Identifier,
    pub username: Cow<'a, str>,
    pub email: Option<EncryptedValue<'a>>,
    pub added_on: DateTime<Utc>,
    pub last_seen_on: DateTime<Utc>,
    pub passwords: Vec<Cow<'a, str>>,
    pub sessions: Vec<Cow<'a, str>>,
    pub is_active: bool,
}

impl<'a> User<'a> {
    pub async fn new(
        username: String,
        email: Option<String>,
        password_id: String,
        session_id: String,
    ) -> OperationResult<User<'a>> {
        let email = match email {
            Some(e) => Some(EncryptedValue::new(SecretValue::from(e)).await?),
            None => None,
        };

        Ok(User {
            id: Identifier::default(),
            username: username.into(),
            email,
            added_on: Utc::now(),
            last_seen_on: Utc::now(),
            passwords: vec![password_id.into()],
            sessions: vec![session_id.into()],
            is_active: true,
        })
    }

    pub fn get_id(&self) -> &Identifier {
        &self.id
    }
}

impl From<User<'_>> for pandorica_common::User {
    fn from(value: User) -> Self {
        pandorica_common::User {
            id: value.get_id().as_string(),
            username: value.username.into(),
            email: value
                .email
                .map(|e| e.value().unwrap().as_sensitive_str().into()),
            added_on: value.added_on.timestamp_micros(),
            last_seen_on: value.last_seen_on.timestamp_micros(),
            is_active: value.is_active,
        }
    }
}
