use std::borrow::Cow;

use crypto::encryption::ChaCha20Poly1305;
use crypto::traits::EncryptionProvider;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use shared::error::{EmptyResult, OperationResult};
use singleton::sync::Singleton;

use crate::crypto::KeyProvider;
use crate::models::crypto::Dek;

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedValue<'a> {
    value: Cow<'a, [u8]>,
    dek: Cow<'a, [u8]>,
    #[serde(skip)]
    is_decoded: bool,
    #[serde(skip)]
    decoded_value: SecretValue,
    #[serde(skip)]
    decoded_dek: Dek<'a>,
}

impl<'a> EncryptedValue<'a> {
    pub async fn new(value: SecretValue) -> OperationResult<EncryptedValue<'a>> {
        let dek: Dek;
        {
            let guard = KeyProvider::lock().await;
            dek = guard.generate_dek().await?;
        }

        let encrypted_value = ChaCha20Poly1305::encrypt(&value, &dek.decoded_key, &dek.nonce)?;

        Ok(EncryptedValue {
            value: encrypted_value.into(),
            dek: dek.to_bytes()?.into(),
            is_decoded: true,
            decoded_value: value,
            decoded_dek: dek,
        })
    }

    pub async fn decrypt(&mut self) -> EmptyResult {
        self.decoded_dek = Dek::from_bytes(&self.dek)?;
        {
            let guard = KeyProvider::lock().await;
            guard.decrypt_dek(&mut self.decoded_dek).await?;
        }

        self.decoded_value = ChaCha20Poly1305::decrypt(
            &self.value,
            &self.decoded_dek.decoded_key,
            &self.decoded_dek.nonce,
        )?;

        self.is_decoded = true;

        Ok(())
    }

    pub fn value(&self) -> Option<&SecretValue> {
        if !self.is_decoded {
            return None;
        }

        Some(&self.decoded_value)
    }
}
