use std::fs::File;
use std::io::{Read, Write};

use chacha20poly1305::aead::{stream, Aead};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use secret_vault_value::SecretValue;
use shared::error::OperationResult;

use crate::traits::EncryptionProvider;

#[derive(Clone)]
pub struct ChaCha20Poly1305;

impl EncryptionProvider for ChaCha20Poly1305 {
    fn encrypt(
        plaintext: &SecretValue,
        key: &SecretValue,
        nonce: &[u8],
    ) -> OperationResult<Vec<u8>> {
        let key = Key::from_slice(key.as_sensitive_bytes());
        let nonce = XNonce::from_slice(nonce);
        let cipher = XChaCha20Poly1305::new(key);

        let ciphertext = plaintext.exposed_in_as_zvec(|p| cipher.encrypt(nonce, p.as_slice()))?;

        Ok(ciphertext)
    }

    fn decrypt(ciphertext: &[u8], key: &SecretValue, nonce: &[u8]) -> OperationResult<SecretValue> {
        let key = Key::from_slice(key.as_sensitive_bytes());
        let nonce = XNonce::from_slice(nonce);
        let cipher = XChaCha20Poly1305::new(key);

        let plaintext = cipher.decrypt(nonce, ciphertext)?;

        Ok(plaintext.into())
    }

    fn encrypt_aead(
        plaintext: &mut File,
        key: &[u8],
        nonce: &[u8],
        dest: &mut File,
    ) -> OperationResult<()> {
        let key = Key::from_slice(key);
        let cipher = XChaCha20Poly1305::new(key);
        let mut encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.into());

        const BUFFER_LEN: usize = 10240; // 10 KiB buffer size
        let mut buffer = [0u8; BUFFER_LEN];

        loop {
            let read_count = plaintext.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let ciphertext = encryptor.encrypt_next(buffer.as_slice())?;
                let _ = dest.write(&ciphertext);
            } else {
                let ciphertext = encryptor.encrypt_last(&buffer[..read_count])?;
                let _ = dest.write(&ciphertext);
                break;
            }
        }

        Ok(())
    }

    fn decrypt_aead(
        ciphertext: &mut File,
        key: &[u8],
        nonce: &[u8],
        dest: &mut File,
    ) -> OperationResult<()> {
        let key = Key::from_slice(key);
        let cipher = XChaCha20Poly1305::new(key);
        let mut decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.into());

        const BUFFER_LEN: usize = 10240 + 16; // 10 KiB buffer size, + 16 B for the authentication tag
        let mut buffer = [0u8; BUFFER_LEN];

        loop {
            let read_count = ciphertext.read(&mut buffer)?;

            if read_count == BUFFER_LEN {
                let ciphertext = decryptor.decrypt_next(buffer.as_slice())?;
                let _ = dest.write(&ciphertext);
            } else {
                let ciphertext = decryptor.decrypt_last(&buffer[..read_count])?;
                let _ = dest.write(&ciphertext);
                break;
            }
        }

        Ok(())
    }
}
