use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use surrealdb::sql::Datetime;

#[derive(Serialize, Deserialize, Default)]
pub struct Mk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub added_on: Datetime,
    pub expires_on: Datetime,
    pub is_active: bool,
    pub key: Vec<u8>,
    #[serde(skip)]
    pub decoded_key: SecretValue,
}
