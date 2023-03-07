use scrypt::Params;
use secret_vault_value::SecretValue;
use shared::error::OperationResult;

use crate::traits::KeyDerivationProvider;

#[derive(Clone)]
pub struct Scrypt;

impl KeyDerivationProvider for Scrypt {
    fn derive_key(input: &SecretValue, salt: &[u8]) -> OperationResult<SecretValue> {
        let mut output: Vec<u8> = vec![0; 32];
        scrypt::scrypt(
            input.as_sensitive_bytes(),
            salt,
            &Params::recommended(),
            &mut output,
        )?;

        Ok(output.into())
    }
}
