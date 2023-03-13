use chrono::{DateTime, Duration, Utc};
use foreign::IntoKey;
use identifier::Identifier;
use protobuf::pandorica_common;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Serialize, Deserialize, Clone)]
pub struct Session<'a> {
    #[serde(skip_serializing_if = "Identifier::is_none")]
    id: Identifier,
    pub user_id: Cow<'a, str>,
    pub added_on: DateTime<Utc>,
    pub last_used_on: DateTime<Utc>,
    pub expires_on: DateTime<Utc>,
}

impl<'a> IntoKey for Session<'a> {
    fn get_key(&self) -> String {
        self.id.as_string()
    }
}

impl<'a> Session<'a> {
    pub fn new(user_id: String) -> Self {
        Self {
            id: Identifier::default(),
            user_id: user_id.into(),
            added_on: Utc::now(),
            last_used_on: Utc::now(),
            expires_on: Utc::now() + Duration::hours(8),
        }
    }

    pub fn get_id(&self) -> &Identifier {
        &self.id
    }

    pub fn verify(&self) -> bool {
        self.expires_on > Utc::now()
    }
}

impl From<Session<'_>> for pandorica_common::Session {
    fn from(value: Session<'_>) -> Self {
        pandorica_common::Session {
            id: value.get_id().as_string(),
            user_id: Some(value.user_id.into()),
            added_on: value.added_on.timestamp_millis(),
            last_used_on: value.last_used_on.timestamp_millis(),
            expires_on: value.expires_on.timestamp_millis(),
        }
    }
}
