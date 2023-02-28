use crate::KEY_PROVIDER;
use serde::{Deserialize, Serialize};
use serde_binary::binary_stream::Endian;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Dek {
    #[serde(skip)]
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub master_key_id: String,
    pub wrapping_nonce: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

impl Dek {
    pub fn new(
        key: Vec<u8>,
        nonce: Vec<u8>,
        master_key_id: String,
        wrapping_nonce: Vec<u8>,
        wrapped_key: Vec<u8>,
    ) -> Self {
        Self {
            key,
            nonce,
            master_key_id,
            wrapping_nonce,
            wrapped_key,
        }
    }

    pub async fn decrypt(ciphertext: &[u8]) -> crate::shared::Result<Self> {
        let mut dek = Self::from_bytes(ciphertext);
        {
            let guard = KEY_PROVIDER.lock().await;
            guard.decrypt_dek(&mut dek).await?;
        }

        Ok(dek)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_binary::to_vec(self, Endian::Big).unwrap()
    }

    pub fn from_bytes(encoded: &[u8]) -> Self {
        serde_binary::from_slice(encoded, Endian::Big).unwrap()
    }
}
