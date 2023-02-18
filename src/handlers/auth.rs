use crate::knox_auth::{auth_service_server, AuthResponse, LoginRequest, RegistrationRequest};
use crate::shared::Error;
use crate::{models, CRYPTO, DB};
use async_trait::async_trait;
use tonic::{Request, Response, Status};

#[derive(Default)]
pub struct AuthService {}

#[async_trait]
impl auth_service_server::AuthService for AuthService {
    async fn register(
        &self,
        request: Request<RegistrationRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let mut user: models::User = request.into_inner().into();
        user.validate(true).await?;

        let plaintext = user.password().plaintext().as_bytes();
        let hash = CRYPTO.hashing().generate_hash_ns(plaintext)?;
        user.password_mut().hash = String::from_utf8(hash).map_err(Error::new)?.into();

        let dek = user.dek().await?;

        if user.decoded_email.is_some() {
            let ciphertext = CRYPTO.encryption().encrypt(
                user.decoded_email.clone().unwrap().as_bytes(),
                &dek.key,
                &dek.nonce,
            )?;
            user.email = Some(ciphertext);
        }

        let mut db_user: models::User =
            DB.create("user").content(&user).await.map_err(Error::new)?;
        let password: models::Password = DB
            .create("password")
            .content(&user.password())
            .await
            .map_err(Error::new)?;

        let sql = r#"
            LET $u = type::thing("user", $user);
            LET $p = type::thing("password", $password);
            RELATE $u->auth_with->$p
        "#;

        let _ = DB
            .query(sql)
            .bind(("user", &db_user.id))
            .bind(("password", password.id))
            .await
            .map_err(Error::new)?;

        db_user.decoded_email = user.decoded_email;

        Ok(Response::new(AuthResponse {
            user: Some(db_user.into()),
            authorization_code: "123".into(),
        }))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let user: models::User = request.into_inner().into();
        user.validate(false).await?;

        let sql = r#"
            SELECT *, ->auth_with->password[WHERE is_active = true].* AS passwords
            FROM user
            WHERE username = $username
        "#;

        let db_user: Option<models::User> = DB
            .query(sql)
            .bind(("username", &user.username))
            .await
            .map(|mut r| r.take(0))
            .map_err(Error::new)?
            .map_err(Error::new)?;

        if db_user.is_none() {
            return Err(Status::not_found("user_not_found"));
        }
        let mut db_user = db_user.unwrap();

        let matches = CRYPTO.hashing().verify_hash(
            user.password().plaintext().as_bytes(),
            db_user.password().hash.as_bytes(),
        )?;

        if !matches {
            return Err(Status::permission_denied("invalid_password"));
        }

        if db_user.email.is_some() {
            let dek = db_user.dek().await?;
            let plaintext = CRYPTO.encryption().decrypt(
                db_user.email.clone().unwrap().as_slice(),
                &dek.key,
                &dek.nonce,
            )?;
            db_user.decoded_email = Some(String::from_utf8(plaintext).map_err(Error::new)?.into());
        }

        Ok(Response::new(AuthResponse {
            user: Some(db_user.into()),
            authorization_code: "123".into(),
        }))
    }
}
