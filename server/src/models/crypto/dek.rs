use secret_vault_value::SecretValue;
use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_binary::binary_stream::Endian;
use shared::error::OperationResult;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Dek<'a> {
    pub key: Cow<'a, [u8]>,
    pub nonce: Cow<'a, [u8]>,
    pub wrapping_nonce: Cow<'a, [u8]>,
    pub master_key_id: Cow<'a, str>,
    #[serde(skip)]
    pub decoded_key: SecretValue,
}

impl<'a> Dek<'a> {
    pub fn new(
        key: SecretValue,
        nonce: Vec<u8>,
        master_key_id: String,
        wrapping_nonce: Vec<u8>,
        wrapped_key: Vec<u8>,
    ) -> Self {
        Self {
            decoded_key: key,
            nonce: nonce.into(),
            master_key_id: master_key_id.into(),
            wrapping_nonce: wrapping_nonce.into(),
            key: wrapped_key.into(),
        }
    }

    pub fn to_bytes(&self) -> OperationResult<Vec<u8>> {
        serde_binary::to_vec(self, Endian::Big).map_err(|e| e.into())
    }

    pub fn from_bytes(encoded: &[u8]) -> OperationResult<Self> {
        serde_binary::from_slice(encoded, Endian::Big).map_err(|e| e.into())
    }
}
