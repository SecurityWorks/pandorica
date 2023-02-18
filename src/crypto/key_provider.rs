use crate::models::crypto::{DEK, MK};
use crate::{CRYPTO, DB};
use secret_vault_value::SecretValue;
use surrealdb::sql::Datetime;

const ENCRYPTION_KEY_SIZE: u32 = 32;
const ENCRYPTION_NONCE_SIZE: u32 = 24;

#[derive(Default)]
pub struct KeyProvider {
    current_master_key: MK,
}

impl KeyProvider {
    pub async fn init(&mut self) -> crate::shared::Result<()> {
        self.rotate().await
    }

    pub async fn rotate(&mut self) -> crate::shared::Result<()> {
        let result = self.load_master_key(None).await;

        if result.is_ok() {
            if self.current_master_key.expires_on > Datetime::from(chrono::Utc::now()) {
                return Ok(());
            }

            let _ = DB
                .query(
                    r#"
                        UPDATE master_key
                        SET is_active = false
                        WHERE id = $id
                    "#,
                )
                .bind(("id", self.current_master_key.id.clone().unwrap()))
                .await?;
        }

        if let Some(e) = result.err() {
            if e.to_string() != "master_key_not_found" {
                return Err(e);
            }
        }

        let key_material = CRYPTO.cloud().generate_random_bytes(32).await?;
        let wrapped_key_material = CRYPTO
            .cloud()
            .encrypt_envelope(&key_material, "pandorica-master".into())
            .await?;

        let master_key = MK {
            id: None,
            added_on: Datetime::default(),
            expires_on: Datetime::from(chrono::Utc::now() + chrono::Duration::days(90)),
            is_active: true,
            key: wrapped_key_material,
            decoded_key: None,
        };

        let mut master_key: MK = DB.create("master_key").content(&master_key).await?;

        master_key.key = Default::default();
        master_key.decoded_key = Some(SecretValue::from(key_material));

        self.current_master_key = master_key;

        Ok(())
    }

    pub async fn generate_dek(&self) -> crate::shared::Result<DEK> {
        let key = CRYPTO
            .cloud()
            .generate_random_bytes(ENCRYPTION_KEY_SIZE)
            .await?;
        let nonce = CRYPTO
            .cloud()
            .generate_random_bytes(ENCRYPTION_NONCE_SIZE)
            .await?;
        let wrapping_nonce = CRYPTO
            .cloud()
            .generate_random_bytes(ENCRYPTION_NONCE_SIZE)
            .await?;
        let wrapped_key_material = CRYPTO.encryption().encrypt(
            &key,
            self.current_master_key
                .decoded_key
                .clone()
                .unwrap()
                .as_sensitive_bytes(),
            &wrapping_nonce,
        )?;

        Ok(DEK::new(
            key,
            nonce,
            self.current_master_key.id.clone().unwrap(),
            wrapping_nonce,
            wrapped_key_material,
        ))
    }

    pub async fn decrypt_dek(&self, dek: &mut DEK) -> crate::shared::Result<()> {
        let master_key = if self.current_master_key.id.clone().unwrap() == dek.master_key_id {
            self.current_master_key.decoded_key.clone().unwrap()
        } else {
            self.load_master_key(Some(dek.master_key_id.clone()))
                .await?
                .decoded_key
                .unwrap()
        };

        let key = CRYPTO.encryption().decrypt(
            &dek.wrapped_key,
            master_key.as_sensitive_bytes(),
            &dek.wrapping_nonce,
        )?;

        dek.key = key;

        Ok(())
    }

    async fn load_master_key(&self, id: Option<String>) -> crate::shared::Result<MK> {
        let query = match id {
            Some(id) => DB
                .query(
                    r#"
                        SELECT *
                        FROM master_key
                        WHERE id = $id
                    "#,
                )
                .bind(("id", id)),
            None => DB.query(
                r#"
                    SELECT *
                    FROM master_key
                    WHERE is_active = true
                "#,
            ),
        };

        let master_key: Option<MK> = query.await.map(|mut r| r.take(0)).unwrap()?;
        let mut master_key = match master_key {
            Some(m) => m,
            None => return Err(crate::shared::Error::new_from("master_key_not_found")),
        };

        let decrypted_key = CRYPTO
            .cloud()
            .decrypt_envelope(&master_key.key, "pandorica-master".into())
            .await?;

        master_key.decoded_key = Some(SecretValue::from(decrypted_key));

        Ok(master_key)
    }
}
