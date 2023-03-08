use std::borrow::Cow;

use foreign::Foreign;
use identifier::Identifier;
use protobuf::pandorica_auth::{LoginRequest, RegistrationRequest};
use protobuf::pandorica_common;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use shared::error::OperationResult;

use crate::models::auth::Password;
use crate::models::crypto::EncryptedValue;

#[derive(Serialize, Deserialize, Clone)]
pub struct User<'a> {
    #[serde(skip_serializing_if = "Identifier::is_none")]
    id: Identifier,
    pub username: Cow<'a, str>,
    pub email: Option<EncryptedValue<'a>>,
    pub password: Foreign<Password<'a>>,
    pub historical_passwords: Foreign<Vec<Password<'a>>>,
    pub is_active: bool,
}

impl<'a> User<'a> {
    pub async fn new(
        username: String,
        email: Option<String>,
        password: SecretValue,
    ) -> OperationResult<User<'a>> {
        let password = Password::new(password)?;
        let email = match email {
            Some(e) => Some(EncryptedValue::new(SecretValue::from(e)).await?),
            None => None,
        };

        Ok(User {
            id: Identifier::default(),
            username: username.into(),
            email,
            password: password.into(),
            historical_passwords: Foreign::default(),
            is_active: true,
        })
    }

    pub async fn from_registration(registration: RegistrationRequest) -> OperationResult<User<'a>> {
        User::new(
            registration.username,
            registration.email,
            registration.password.into(),
        )
        .await
    }

    pub async fn from_login(login: LoginRequest) -> OperationResult<User<'a>> {
        User::new(login.username, None, login.password.into()).await
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
            is_active: value.is_active,
        }
    }
}
