use crate::models::crypto::Dek;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedValue {
    value: Vec<u8>,
    dek: Vec<u8>,
    #[serde(skip)]
    decoded_value: SecretValue,
    #[serde(skip)]
    decoded_dek: Dek,
}

impl EncryptedValue {
    pub async fn new(value: Vec<u8>) -> crate::shared::Result<Self> {
        let dek: Dek;
        {
            let guard = crate::KEY_PROVIDER.lock().await;
            dek = guard.generate_dek().await?;
        }

        let encrypted_value = crate::CRYPTO
            .encryption()
            .encrypt(&value, &dek.key, &dek.nonce)?;

        Ok(EncryptedValue {
            value: encrypted_value,
            dek: dek.to_bytes(),
            decoded_value: SecretValue::new(value),
            decoded_dek: dek,
        })
    }

    pub async fn decrypt(&mut self) -> crate::shared::Result<()> {
        self.decoded_dek = Dek::decrypt(&self.dek).await?;

        let decrypted_value = crate::CRYPTO.encryption().decrypt(
            &self.value,
            &self.decoded_dek.key,
            &self.decoded_dek.nonce,
        )?;

        self.decoded_value = SecretValue::new(decrypted_value);

        Ok(())
    }

    pub fn value(&self) -> &SecretValue {
        &self.decoded_value
    }
}
