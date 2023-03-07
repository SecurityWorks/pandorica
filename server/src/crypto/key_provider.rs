use crate::config::Settings;
use chrono::Utc;
use crypto::encryption::chacha20poly1305::ChaCha20Poly1305;
use crypto::traits::{CloudProvider, EncryptionProvider};
use secret_vault_value::SecretValue;
use shared::error::{EmptyResult, OperationResult};
use singleton::{unsync::Singleton as UnsyncSingleton, OnceCell, Singleton, SingletonInit};
use std::borrow::Cow;

use crate::models::crypto::{Dek, Mk};
use crate::repos;

const ENCRYPTION_KEY_SIZE: u32 = 32;
const ENCRYPTION_NONCE_SIZE: u32 = 24;

#[derive(Default, Singleton)]
#[singleton(use_once_cell = false)]
pub struct KeyProvider {
    hsm: OnceCell<Box<dyn CloudProvider>>,
    current_master_key: Cow<'static, Mk<'static>>,
}

impl KeyProvider {
    pub async fn init_cloud(&mut self) -> EmptyResult {
        if Settings::get().crypto.hsm_provider == "gcp" {
            self.hsm =
                OnceCell::from(Box::<crypto::hsm::gcp::Gcp>::default() as Box<dyn CloudProvider>);
        }

        self.hsm
            .get_mut()
            .unwrap()
            .init(
                &Settings::get().gcp.as_ref().unwrap().project_id,
                &Settings::get().gcp.as_ref().unwrap().location,
                &Settings::get().gcp.as_ref().unwrap().key_ring,
            )
            .await?;
        self.rotate().await
    }

    pub async fn rotate(&mut self) -> EmptyResult {
        let result = self.load_master_key(None).await;

        match result {
            Ok(mut mk) => {
                if mk.expires_on > Utc::now() {
                    self.current_master_key = Cow::Owned(mk);
                    return Ok(());
                }

                mk.is_active = false;
                repos::mk::update(&mk).await?;
            }
            Err(e) => {
                if e.to_string() != "master_key_not_found" {
                    return Err(e);
                }
            }
        }

        let key_material =
            SecretValue::from(self.hsm.get().unwrap().generate_random_bytes(32).await?);
        let wrapped_key_material = self
            .hsm
            .get()
            .unwrap()
            .encrypt_envelope(
                key_material.clone(),
                Settings::get().gcp.as_ref().unwrap().key.as_ref(),
            )
            .await?;

        let master_key = Mk::new(wrapped_key_material);
        let mut master_key: Mk = repos::mk::create(master_key).await?;

        master_key.key = Default::default();
        master_key.decoded_key = Some(key_material);

        self.current_master_key = Cow::Owned(master_key);

        Ok(())
    }

    pub async fn generate_dek<'a>(&self) -> OperationResult<Dek<'a>> {
        let key = SecretValue::from(
            self.hsm
                .get()
                .unwrap()
                .generate_random_bytes(ENCRYPTION_KEY_SIZE)
                .await?,
        );
        let nonce = self
            .hsm
            .get()
            .unwrap()
            .generate_random_bytes(ENCRYPTION_NONCE_SIZE)
            .await?;
        let wrapping_nonce = self
            .hsm
            .get()
            .unwrap()
            .generate_random_bytes(ENCRYPTION_NONCE_SIZE)
            .await?;
        let wrapped_key_material = ChaCha20Poly1305::encrypt(
            &key,
            &self.current_master_key.decoded_key.clone().unwrap(),
            &wrapping_nonce,
        )?;

        Ok(Dek::new(
            key,
            nonce,
            String::from(self.current_master_key.get_id().partial_identifier()),
            wrapping_nonce,
            wrapped_key_material,
        ))
    }

    pub async fn decrypt_dek(&self, dek: &'_ mut Dek<'_>) -> EmptyResult {
        let master_key = self
            .load_master_key(Some(dek.master_key_id.as_ref()))
            .await?;

        let key = ChaCha20Poly1305::decrypt(
            &dek.key,
            master_key.decoded_key.as_ref().unwrap(),
            &dek.wrapping_nonce,
        )?;

        dek.decoded_key = key;

        Ok(())
    }

    async fn load_master_key<'a>(&self, id: Option<&'a str>) -> OperationResult<Mk<'a>> {
        let master_key = match id {
            Some(id) => repos::mk::read(id).await,
            None => repos::mk::read_current().await,
        }?;

        let mut master_key = match master_key {
            Some(m) => Ok(m),
            None => Err(anyhow::Error::msg("master_key_not_found")),
        }?;

        self.decrypt_master_key(&mut master_key).await?;

        Ok(master_key)
    }

    async fn decrypt_master_key<'a>(&self, master_key: &mut Mk<'a>) -> EmptyResult {
        let decrypted_key = self
            .hsm
            .get()
            .unwrap()
            .decrypt_envelope(
                &master_key.key,
                Settings::get().gcp.as_ref().unwrap().key.as_ref(),
            )
            .await?;

        master_key.decoded_key = Some(decrypted_key);

        Ok(())
    }
}

impl SingletonInit<KeyProvider> for KeyProvider {
    fn init() -> KeyProvider {
        KeyProvider::default()
    }
}
