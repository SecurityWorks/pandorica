use crate::crypto::encryption::ChaCha20Poly1305;
use crate::crypto::envelope::GCP;
use crate::crypto::hashing::Argon2id;
use crate::crypto::keyderivation::Scrypt;
use crate::crypto::traits::{
    CloudProvider, EncryptionProvider, HashingProvider, KeyDerivationProvider,
};
use crate::throw_error;
use std::sync::Arc;

pub struct CryptoProvider {
    encryption_provider: Arc<Box<dyn EncryptionProvider>>,
    hashing_provider: Arc<Box<dyn HashingProvider>>,
    keyderivation_provider: Arc<Box<dyn KeyDerivationProvider>>,
    cloud_provider: Arc<Box<dyn CloudProvider>>,
}

impl CryptoProvider {
    pub async fn new(
        encryption: String,
        hashing: String,
        keyderivation: String,
        envelope: String,
    ) -> crate::shared::Result<Self> {
        Ok(CryptoProvider {
            encryption_provider: CryptoProvider::construct_encryption(encryption),
            hashing_provider: CryptoProvider::construct_hashing(hashing),
            keyderivation_provider: CryptoProvider::construct_keyderivation(keyderivation),
            cloud_provider: CryptoProvider::construct_envelope(envelope).await?,
        })
    }

    pub fn encryption(&self) -> &dyn EncryptionProvider {
        self.encryption_provider.as_ref().as_ref()
    }

    pub fn hashing(&self) -> &dyn HashingProvider {
        self.hashing_provider.as_ref().as_ref()
    }

    pub fn keyderivation(&self) -> &dyn KeyDerivationProvider {
        self.keyderivation_provider.as_ref().as_ref()
    }

    pub fn cloud(&self) -> &dyn CloudProvider {
        self.cloud_provider.as_ref().as_ref()
    }

    fn construct_encryption(encryption: String) -> Arc<Box<dyn EncryptionProvider>> {
        match encryption.as_str() {
            "chacha20poly1305" => Arc::new(Box::new(ChaCha20Poly1305)),
            _ => throw_error!("Encryption provider {} not found", encryption),
        }
    }

    fn construct_hashing(hashing: String) -> Arc<Box<dyn HashingProvider>> {
        match hashing.as_str() {
            "argon2id" => Arc::new(Box::new(Argon2id)),
            _ => throw_error!("Hashing provider {} not found", hashing),
        }
    }

    fn construct_keyderivation(keyderivation: String) -> Arc<Box<dyn KeyDerivationProvider>> {
        match keyderivation.as_str() {
            "scrypt" => Arc::new(Box::new(Scrypt)),
            _ => throw_error!("Key derivation provider {} not found", keyderivation),
        }
    }

    async fn construct_envelope(
        envelope: String,
    ) -> crate::shared::Result<Arc<Box<dyn CloudProvider>>> {
        match envelope.as_str() {
            "gcp" => Ok(Arc::new(Box::new(GCP::new().await?))),
            _ => throw_error!("Envelope provider {} not found", envelope),
        }
    }
}
