use crate::crypto::traits::CloudProvider;
use crate::CONFIG;
use async_trait::async_trait;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::{DecryptRequest, GenerateRandomBytesRequest};
use gcloud_sdk::proto_ext::kms::EncryptRequest;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use secret_vault_value::SecretValue;
use tonic::metadata::MetadataValue;

pub struct Gcp {
    kms_service: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    location: String,
    keyring: String,
}

impl Gcp {
    pub async fn new() -> crate::shared::Result<Self> {
        let kms_service = GoogleApi::from_function(
            KeyManagementServiceClient::new,
            "https://cloudkms.googleapis.com",
            None,
        )
        .await?;

        let location = format!(
            "projects/{}/locations/{}",
            CONFIG.gcp_project_id(),
            CONFIG.gcp_keyring_location()
        );

        let keyring = format!(
            "{}/keyRings/{}/cryptoKeys",
            location,
            CONFIG.gcp_keyring_name()
        );

        Ok(Self {
            kms_service,
            keyring,
            location,
        })
    }
}

#[async_trait]
impl CloudProvider for Gcp {
    async fn encrypt_envelope(
        &self,
        plaintext: &[u8],
        key: String,
    ) -> crate::shared::Result<Vec<u8>> {
        let key = format!("{}/{}", self.keyring.clone(), key);

        let mut encrypt_request = tonic::Request::new(EncryptRequest {
            name: key.clone(),
            plaintext: SecretValue::from(plaintext.to_vec()),
            additional_authenticated_data: vec![],
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        });

        encrypt_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!("name={}", key)).unwrap(),
        );

        let response = &self.kms_service.get().encrypt(encrypt_request).await?;

        let response = response.get_ref().clone();

        Ok(response.ciphertext)
    }

    async fn decrypt_envelope(
        &self,
        ciphertext: &[u8],
        key: String,
    ) -> crate::shared::Result<Vec<u8>> {
        let key = format!("{}/{}", self.keyring.clone(), key);

        let mut decrypt_request = tonic::Request::new(DecryptRequest {
            name: key.clone(),
            ciphertext: ciphertext.into(),
            additional_authenticated_data: vec![],
            ciphertext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        });

        decrypt_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!("name={}", key)).unwrap(),
        );

        let response = &self.kms_service.get().decrypt(decrypt_request).await?;

        let response = response.get_ref().clone();

        Ok(response.plaintext.as_sensitive_bytes().to_vec())
    }

    async fn generate_random_bytes(&self, size: u32) -> crate::shared::Result<Vec<u8>> {
        let mut generate_random_bytes_request = tonic::Request::new(GenerateRandomBytesRequest {
            location: self.location.clone(),
            length_bytes: size as i32,
            protection_level: 2,
        });

        generate_random_bytes_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!(
                "name={}",
                self.location.clone()
            ))
            .unwrap(),
        );

        let response = &self
            .kms_service
            .get()
            .generate_random_bytes(generate_random_bytes_request)
            .await?;

        let response = response.get_ref().clone();

        Ok(response.data)
    }
}
