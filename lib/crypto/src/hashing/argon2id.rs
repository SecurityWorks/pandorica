use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand_core::OsRng;
use secret_vault_value::SecretValue;
use shared::error::OperationResult;

use crate::traits::HashingProvider;

#[derive(Clone)]
pub struct Argon2id;

impl HashingProvider for Argon2id {
    fn generate_hash(plaintext: &SecretValue, salt: &[u8]) -> OperationResult<Vec<u8>> {
        let salt_string = std::str::from_utf8(salt)?;
        let salt_internal = SaltString::new(salt_string)?;
        let hash = plaintext.exposed_in_as_zvec(|p| {
            Argon2::default().hash_password(p.as_slice(), &salt_internal)
        })?;
        Ok(hash.serialize().as_bytes().into())
    }

    fn generate_hash_ns(plaintext: &SecretValue) -> OperationResult<Vec<u8>> {
        let salt = SaltString::generate(&mut OsRng);

        Argon2id::generate_hash(plaintext, salt.as_bytes())
    }

    fn verify_hash(plaintext: &[u8], hash: &[u8]) -> OperationResult<bool> {
        let password_string = std::str::from_utf8(hash)?;
        let password_hash = PasswordHash::new(password_string)?;
        Ok(Argon2::default()
            .verify_password(plaintext, &password_hash)
            .is_ok())
    }
}
