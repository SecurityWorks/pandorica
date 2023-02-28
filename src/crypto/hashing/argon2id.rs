use crate::crypto::traits::HashingProvider;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand_core::OsRng;

#[derive(Clone)]
pub struct Argon2id;

impl HashingProvider for Argon2id {
    fn generate_hash(&self, plaintext: &[u8], salt: &[u8]) -> crate::shared::Result<Vec<u8>> {
        let salt_string = std::str::from_utf8(salt)?;
        let salt_internal = SaltString::new(salt_string)?;
        let hash = Argon2::default().hash_password(plaintext, &salt_internal)?;
        Ok(hash.serialize().as_bytes().into())
    }

    fn generate_hash_ns(&self, plaintext: &[u8]) -> crate::shared::Result<Vec<u8>> {
        let salt = SaltString::generate(&mut OsRng);

        self.generate_hash(plaintext, salt.as_bytes())
    }

    fn verify_hash(&self, ciphertext: &[u8], hash: &[u8]) -> crate::shared::Result<bool> {
        let password_string = std::str::from_utf8(hash)?;
        let password_hash = PasswordHash::new(password_string)?;
        Ok(Argon2::default()
            .verify_password(ciphertext, &password_hash)
            .is_ok())
    }
}
