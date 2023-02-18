use async_trait::async_trait;
use std::fs::File;

pub trait KeyDerivationProvider: Send + Sync {
    fn derive_key(&self, input: &[u8], salt: &[u8]) -> crate::shared::Result<Vec<u8>>;
}

pub trait HashingProvider: Send + Sync {
    fn generate_hash(&self, plaintext: &[u8], salt: &[u8]) -> crate::shared::Result<Vec<u8>>;
    fn generate_hash_ns(&self, plaintext: &[u8]) -> crate::shared::Result<Vec<u8>>;
    fn verify_hash(&self, ciphertext: &[u8], hash: &[u8]) -> crate::shared::Result<bool>;
}

pub trait EncryptionProvider: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8])
        -> crate::shared::Result<Vec<u8>>;
    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> crate::shared::Result<Vec<u8>>;

    fn encrypt_aead(
        &self,
        plaintext: &mut File,
        key: &[u8],
        nonce: &[u8],
        dest: &mut File,
    ) -> crate::shared::Result<()>;
    fn decrypt_aead(
        &self,
        ciphertext: &mut File,
        key: &[u8],
        nonce: &[u8],
        dest: &mut File,
    ) -> crate::shared::Result<()>;
}

#[async_trait]
pub trait CloudProvider: Send + Sync {
    async fn encrypt_envelope(
        &self,
        plaintext: &[u8],
        key: String,
    ) -> crate::shared::Result<Vec<u8>>;

    async fn decrypt_envelope(
        &self,
        ciphertext: &[u8],
        key: String,
    ) -> crate::shared::Result<Vec<u8>>;

    async fn generate_random_bytes(&self, size: u32) -> crate::shared::Result<Vec<u8>>;
}
