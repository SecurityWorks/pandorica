use crate::models::crypto::DEK;
use crate::models::Password;
use crate::{knox_auth, knox_common, shared, DB};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

lazy_static! {
    static ref USERNAME_REGEX: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9_.]{3,32}$").unwrap();
}

#[derive(Serialize, Deserialize)]
pub struct User {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub username: Cow<'static, str>,
    pub email: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub decoded_email: Option<Cow<'static, str>>,
    #[serde(skip_serializing)]
    pub passwords: Option<Vec<Password>>,
    pub is_active: bool,
    pub dek: Vec<u8>,
}

impl User {
    pub fn password(&self) -> &Password {
        &self.passwords.as_ref().unwrap()[0]
    }

    pub fn password_mut(&mut self) -> &mut Password {
        &mut self.passwords.as_mut().unwrap()[0]
    }

    pub async fn dek(&mut self) -> crate::shared::Result<DEK> {
        if self.dek.is_empty() {
            let dek = DEK::generate().await?;
            self.dek = dek.clone().to_bytes();
            return Ok(dek);
        }

        DEK::decode(&self.dek).await
    }

    pub async fn validate(&self, check_duplicates: bool) -> shared::Result<()> {
        if !USERNAME_REGEX.is_match(&self.username) {
            return Err(shared::Error::new_from("invalid_username"));
        }

        if let Some(e) = &self.decoded_email {
            if !validator::validate_email(e.clone().to_string()) {
                return Err(shared::Error::new_from("invalid_email"));
            }
        }

        if self.passwords.is_none() {
            return Err(shared::Error::new_from("no_passwords"));
        }

        if let Some(p) = &self.passwords {
            for password in p {
                password.validate().await?;
            }
        }

        if !check_duplicates {
            return Ok(());
        }

        self.validate_username().await?;

        Ok(())
    }

    async fn validate_username(&self) -> shared::Result<()> {
        Self::validate_field("username", &self.username)
            .await
            .map_err(|_| shared::Error::new_from("duplicate_username"))?;

        Ok(())
    }

    async fn validate_field(field: &str, value: &str) -> shared::Result<()> {
        let sql = format!(
            r#"
            SELECT *
            FROM type::table($table)
            WHERE {0} = ${0}
        "#,
            field
        );

        let result = DB
            .query(sql)
            .bind(("table", "user"))
            .bind((field, value))
            .await
            .map(|mut r| r.take(0))
            .unwrap()
            .map(|r: Option<User>| r.is_some())?;

        if !result {
            return Ok(());
        }

        Err(shared::Error::empty())
    }
}

impl From<knox_auth::RegistrationRequest> for User {
    fn from(r: knox_auth::RegistrationRequest) -> Self {
        User {
            id: None,
            username: r.username.into(),
            decoded_email: r.email.map(|e| e.into()),
            passwords: Some(vec![Password {
                id: None,
                plaintext: Some(r.password.into()),
                hash: Default::default(),
                added_on: Default::default(),
                is_active: true,
            }]),
            is_active: true,
            email: None,
            dek: Default::default(),
        }
    }
}

impl From<knox_auth::LoginRequest> for User {
    fn from(r: knox_auth::LoginRequest) -> Self {
        User {
            id: None,
            username: r.username.into(),
            email: None,
            passwords: Some(vec![Password {
                id: None,
                plaintext: Some(r.password.into()),
                hash: Default::default(),
                added_on: Default::default(),
                is_active: true,
            }]),
            is_active: true,
            decoded_email: None,
            dek: Default::default(),
        }
    }
}

impl From<User> for knox_common::User {
    fn from(value: User) -> Self {
        knox_common::User {
            id: value.id.unwrap(),
            username: value.username.into(),
            email: value.decoded_email.map(|e| e.into()),
            is_active: value.is_active,
        }
    }
}
