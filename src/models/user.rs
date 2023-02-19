use crate::models::crypto::EncryptedValue;
use crate::models::Password;
use crate::shared::Error;
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
    pub email: Option<EncryptedValue>,
    #[serde(skip_serializing)]
    pub passwords: Option<Vec<Password>>,
    pub is_active: bool,
}

impl User {
    pub fn get_password(&self) -> &Password {
        &self.passwords.as_ref().unwrap()[0]
    }

    pub fn get_password_mut(&mut self) -> &mut Password {
        &mut self.passwords.as_mut().unwrap()[0]
    }

    pub async fn set_email(&mut self, email: Option<String>) -> shared::Result<()> {
        if email.is_none() {
            self.email = None;
            return Ok(());
        }

        self.email = Some(EncryptedValue::new(email.unwrap().into_bytes()).await?);
        Ok(())
    }

    pub async fn validate(&self, check_duplicates: bool) -> shared::Result<()> {
        if !USERNAME_REGEX.is_match(&self.username) {
            return Err(shared::Error::new_from("invalid_username"));
        }

        if let Some(e) = &self.email {
            if e.value()
                .exposed_in_as_zstr(|email| !validator::validate_email(email.as_str()))
            {
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
        let sql = r#"
            SELECT *
            FROM user
            WHERE username = $username
        "#;

        let result = DB
            .query(sql)
            .bind(("username", &self.username))
            .await
            .map(|mut r| r.take(0))
            .unwrap()
            .map(|r: Option<User>| r.is_some())?;

        if !result {
            return Ok(());
        }

        Err(Error::new_from("duplicate_username"))
    }
}

impl From<knox_auth::RegistrationRequest> for User {
    fn from(r: knox_auth::RegistrationRequest) -> Self {
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
        }
    }
}

impl From<User> for knox_common::User {
    fn from(value: User) -> Self {
        knox_common::User {
            id: value.id.unwrap(),
            username: value.username.into(),
            email: value.email.map(|e| e.value().as_sensitive_str().into()),
            is_active: value.is_active,
        }
    }
}
