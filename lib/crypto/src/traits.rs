use std::fs::File;

use async_trait::async_trait;
use secret_vault_value::SecretValue;
use shared::error::{EmptyResult, OperationResult};

pub trait KeyDerivationProvider: Send + Sync {
    fn derive_key(input: &SecretValue, salt: &[u8]) -> OperationResult<SecretValue>;
}

pub trait HashingProvider: Send + Sync {
    fn generate_hash(plaintext: &SecretValue, salt: &[u8]) -> OperationResult<Vec<u8>>;
    fn generate_hash_ns(plaintext: &SecretValue) -> OperationResult<Vec<u8>>;
    fn verify_hash(plaintext: &[u8], hash: &[u8]) -> OperationResult<bool>;
}

pub trait EncryptionProvider: Send + Sync {
    fn encrypt(
        plaintext: &SecretValue,
        key: &SecretValue,
        nonce: &[u8],
    ) -> OperationResult<Vec<u8>>;
    fn decrypt(ciphertext: &[u8], key: &SecretValue, nonce: &[u8]) -> OperationResult<SecretValue>;

    fn encrypt_aead(
        plaintext: &mut File,
        key: &[u8],
        nonce: &[u8],
        dest: &mut File,
    ) -> OperationResult<()>;
    fn decrypt_aead(
        ciphertext: &mut File,
        key: &[u8],
        nonce: &[u8],
        dest: &mut File,
    ) -> OperationResult<()>;
}

#[async_trait]
pub trait CloudProvider: Send + Sync {
    async fn init(&mut self, project_id: &str, location: &str, key_ring: &str) -> EmptyResult;
    async fn encrypt_envelope(&self, plaintext: SecretValue, key: &str)
        -> OperationResult<Vec<u8>>;
    async fn decrypt_envelope(&self, ciphertext: &[u8], key: &str) -> OperationResult<SecretValue>;
    async fn generate_random_bytes(&self, size: u32) -> OperationResult<Vec<u8>>;
}
