use crate::crypto::encryption::ChaCha20Poly1305;
use crate::crypto::envelope::Gcp;
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
    #[allow(dead_code)]
    key_derivation_provider: Arc<Box<dyn KeyDerivationProvider>>,
    cloud_provider: Arc<Box<dyn CloudProvider>>,
}

impl CryptoProvider {
    pub async fn new(
        encryption: &str,
        hashing: &str,
        key_derivation: &str,
        envelope: &str,
    ) -> crate::shared::Result<Self> {
        Ok(CryptoProvider {
            encryption_provider: CryptoProvider::construct_encryption(encryption),
            hashing_provider: CryptoProvider::construct_hashing(hashing),
            key_derivation_provider: CryptoProvider::construct_key_derivation(key_derivation),
            cloud_provider: CryptoProvider::construct_envelope(envelope).await?,
        })
    }

    pub fn encryption(&self) -> &dyn EncryptionProvider {
        self.encryption_provider.as_ref().as_ref()
    }

    pub fn hashing(&self) -> &dyn HashingProvider {
        self.hashing_provider.as_ref().as_ref()
    }

    #[allow(dead_code)]
    pub fn key_derivation(&self) -> &dyn KeyDerivationProvider {
        self.key_derivation_provider.as_ref().as_ref()
    }

    pub fn cloud(&self) -> &dyn CloudProvider {
        self.cloud_provider.as_ref().as_ref()
    }

    fn construct_encryption(encryption: &str) -> Arc<Box<dyn EncryptionProvider>> {
        match encryption {
            "chacha20poly1305" => Arc::new(Box::new(ChaCha20Poly1305)),
            _ => throw_error!("Encryption provider {} not found", encryption),
        }
    }

    fn construct_hashing(hashing: &str) -> Arc<Box<dyn HashingProvider>> {
        match hashing {
            "argon2id" => Arc::new(Box::new(Argon2id)),
            _ => throw_error!("Hashing provider {} not found", hashing),
        }
    }

    fn construct_key_derivation(key_derivation: &str) -> Arc<Box<dyn KeyDerivationProvider>> {
        match key_derivation {
            "scrypt" => Arc::new(Box::new(Scrypt)),
            _ => throw_error!("Key derivation provider {} not found", key_derivation),
        }
    }

    async fn construct_envelope(
        envelope: &str,
    ) -> crate::shared::Result<Arc<Box<dyn CloudProvider>>> {
        match envelope {
            "gcp" => Ok(Arc::new(Box::new(Gcp::new().await?))),
            _ => throw_error!("Envelope provider {} not found", envelope),
        }
    }
}
