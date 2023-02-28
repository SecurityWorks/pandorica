use crate::shared;
use lazy_static::lazy_static;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use surrealdb::sql::Datetime;

lazy_static! {
    static ref PASSWORD_UPPER_REGEX: regex::Regex = regex::Regex::new(r"[A-Z]+").unwrap();
    static ref PASSWORD_LOWER_REGEX: regex::Regex = regex::Regex::new(r"[a-z]+").unwrap();
    static ref PASSWORD_DIGIT_REGEX: regex::Regex = regex::Regex::new(r"[0-9]+").unwrap();
    static ref PASSWORD_SPECIAL_REGEX: regex::Regex =
        regex::Regex::new(r#"[ !"$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]+"#).unwrap();
}

#[derive(Serialize, Deserialize)]
pub struct Password {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip)]
    pub plaintext: Option<SecretValue>,
    pub hash: Cow<'static, str>,
    pub added_on: Datetime,
    pub is_active: bool,
}

impl Password {
    pub async fn validate(&self) -> shared::Result<()> {
        if let Some(p) = &self.plaintext {
            if p.as_sensitive_str().len() < 8_usize
                || !PASSWORD_UPPER_REGEX.is_match(p.as_sensitive_str())
                || !PASSWORD_LOWER_REGEX.is_match(p.as_sensitive_str())
                || !PASSWORD_DIGIT_REGEX.is_match(p.as_sensitive_str())
                || !PASSWORD_SPECIAL_REGEX.is_match(p.as_sensitive_str())
            {
                return Err(shared::Error::new_from("invalid_password"));
            }
        }

        Ok(())
    }
}
