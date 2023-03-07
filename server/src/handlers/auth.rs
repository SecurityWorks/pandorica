use shared::error::EmptyResult;
use singleton::async_trait;
use tonic::{Request, Response, Status};

use crate::knox_auth::{auth_service_server, AuthResponse, LoginRequest, RegistrationRequest};
use crate::models::auth::User;
use crate::{repos, validators};

#[derive(Default)]
pub struct AuthService {}

#[async_trait]
impl auth_service_server::AuthService for AuthService {
    async fn register(
        &self,
        request: Request<RegistrationRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let request = request.into_inner();
        let user = User::from_registration(request).await?;
        EmptyResult::from(validators::user(&user).await)?;
        EmptyResult::from(validators::user_duplicate(&user).await)?;

        let mut user = repos::user::create(user).await?;
        if user.email.is_some() {
            user.email.as_mut().unwrap().decrypt().await?;
        }

        Ok(Response::new(AuthResponse {
            user: Some(user.into()),
            authorization_code: "123".into(),
        }))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let request = request.into_inner();
        let user = User::from_login(request).await?;
        EmptyResult::from(validators::user(&user).await)?;

        let db_user = repos::user::read_by_username(&user.username).await?;

        if db_user.is_none() {
            return Err(Status::not_found("user_not_found"));
        }
        let mut db_user = db_user.unwrap();

        if !user
            .password
            .value()
            .unwrap()
            .verify(db_user.password.value().unwrap())?
        {
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
