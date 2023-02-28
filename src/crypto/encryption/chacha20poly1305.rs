use crate::crypto::traits::EncryptionProvider;
use chacha20poly1305::aead::{stream, Aead};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use std::fs::File;
use std::io::{Read, Write};

#[derive(Clone)]
pub struct ChaCha20Poly1305;

impl EncryptionProvider for ChaCha20Poly1305 {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> crate::shared::Result<Vec<u8>> {
        let key = Key::from_slice(key);
        let nonce = XNonce::from_slice(nonce);
        let cipher = XChaCha20Poly1305::new(key);

        let ciphertext = cipher.encrypt(nonce, plaintext)?;

        Ok(ciphertext)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> crate::shared::Result<Vec<u8>> {
        let key = Key::from_slice(key);
        let nonce = XNonce::from_slice(nonce);
        let cipher = XChaCha20Poly1305::new(key);

        let plaintext = cipher.decrypt(nonce, ciphertext)?;

        Ok(plaintext)
    }

    fn encrypt_aead(
        &self,
        plaintext: &mut File,
        key: &[u8],
        nonce: &[u8],
        dest: &mut File,
    ) -> crate::shared::Result<()> {
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
        &self,
        ciphertext: &mut File,
        key: &[u8],
        nonce: &[u8],
        dest: &mut File,
    ) -> crate::shared::Result<()> {
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
