use crate::crypto::traits::KeyDerivationProvider;
use scrypt::Params;

#[derive(Clone)]
pub struct Scrypt;

impl KeyDerivationProvider for Scrypt {
    fn derive_key(&self, input: &[u8], salt: &[u8]) -> crate::shared::Result<Vec<u8>> {
        let mut output: Vec<u8> = vec![0; 32];
        scrypt::scrypt(input, salt, &Params::recommended(), &mut output)?;

        Ok(output)
    }
}
