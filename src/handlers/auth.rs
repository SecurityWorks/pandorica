use crate::knox_auth::{auth_service_server, AuthResponse, LoginRequest, RegistrationRequest};
use crate::{models, shared, CRYPTO, DB};
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
        let request = request.into_inner();
        let email = request.email.clone();
        let mut user: models::User = request.into();
        user.set_email(email).await?;
        user.validate(true).await?;

        let hash: String = user
            .get_password()
            .plaintext
            .as_ref()
            .unwrap()
            .exposed_in_as_zstr(|p| {
                let hash = CRYPTO.hashing().generate_hash_ns(p.as_bytes())?;
                String::from_utf8(hash).map_err(shared::Error::new)
            })?;
        user.get_password_mut().hash = hash.into();

        let password: models::Password = DB
            .create("password")
            .content(&user.get_password())
            .await
            .map_err(shared::Error::new)?;

        let mut user: models::User = DB
            .create("user")
            .content(user)
            .await
            .map_err(shared::Error::new)?;
        if user.email.is_some() {
            user.email.as_mut().unwrap().decrypt().await?;
        }

        let sql = r#"
            LET $u = type::thing("user", $user);
            LET $p = type::thing("password", $password);
            RELATE $u->auth_with->$p
        "#;

        let _ = DB
            .query(sql)
            .bind(("user", &user.id))
            .bind(("password", password.id))
            .await
            .map_err(shared::Error::new)?;

        Ok(Response::new(AuthResponse {
            user: Some(user.into()),
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
            .map_err(shared::Error::new)?
            .map_err(shared::Error::new)?;

        if db_user.is_none() {
            return Err(Status::not_found("user_not_found"));
        }
        let mut db_user = db_user.unwrap();

        let matches = user
            .get_password()
            .plaintext
            .as_ref()
            .unwrap()
            .exposed_in_as_zstr(|p| {
                CRYPTO
                    .hashing()
                    .verify_hash(p.as_bytes(), db_user.get_password().hash.as_bytes())
            })?;

        if !matches {
            return Err(Status::permission_denied("invalid_password"));
        }

        if db_user.email.is_some() {
            db_user.email.as_mut().unwrap().decrypt().await?;
        }

        Ok(Response::new(AuthResponse {
            user: Some(db_user.into()),
            authorization_code: "123".into(),
        }))
    }
}
