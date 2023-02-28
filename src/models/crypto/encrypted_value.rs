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

        let encrypted_value: Vec<u8> = dek.key.exposed_in_as_zstr(|k| {
            crate::CRYPTO
                .encryption()
                .encrypt(&value, k.as_bytes(), &dek.nonce)
        })?;

        Ok(EncryptedValue {
            value: encrypted_value,
            dek: dek.to_bytes(),
            decoded_value: SecretValue::new(value),
            decoded_dek: dek,
        })
    }

    pub async fn decrypt(&mut self) -> crate::shared::Result<()> {
        self.decoded_dek = Dek::decrypt(&self.dek).await?;

        let decrypted_value = self.decoded_dek.key.exposed_in_as_zstr(|k| {
            crate::CRYPTO
                .encryption()
                .decrypt(&self.value, k.as_bytes(), &self.decoded_dek.nonce)
        })?;

        self.decoded_value = SecretValue::new(decrypted_value);

        Ok(())
    }

    pub fn value(&self) -> &SecretValue {
        &self.decoded_value
    }
}
