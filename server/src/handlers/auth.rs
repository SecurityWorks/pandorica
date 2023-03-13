use async_trait::async_trait;
use chrono::Utc;
use shared::error::EmptyResult;
use std::borrow::Cow;
use tonic::{Request, Response, Status};

use crate::helpers::authorization::get_session;
use crate::models::auth::{Password, Session, User};
use crate::{repos, validators};
use protobuf::pandorica_auth::{
    auth_service_server, AuthResponse, LoginRequest, RegistrationRequest,
};

#[derive(Default)]
pub struct AuthService {}

#[async_trait]
impl auth_service_server::AuthService for AuthService {
    async fn register(
        &self,
        request: Request<RegistrationRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let request = request.into_inner();

        EmptyResult::from(validators::username_format(request.username.as_str()))?;
        EmptyResult::from(validators::username_duplicate(request.username.as_str()).await)?;
        EmptyResult::from(validators::email(request.email.as_ref()))?;
        EmptyResult::from(validators::password(request.password.as_str()))?;

        let password = Password::new(request.password.into(), String::default())?;
        let mut password = repos::password::create(password).await?;

        let session = Session::new(String::default());
        let mut session = repos::session::create(session).await?;

        let user = User::new(
            request.username,
            request.email,
            password.get_id().full_identifier().to_string(),
            session.get_id().full_identifier().to_string(),
        )
        .await?;
        let mut user = repos::user::create(user).await?;

        password.user_id = user.get_id().full_identifier().to_string().into();
        repos::password::update(&password).await?;

        session.user_id = user.get_id().full_identifier().to_string().into();
        repos::session::update(&session).await?;

        if user.email.is_some() {
            user.email.as_mut().unwrap().decrypt().await?;
        }

        Ok(Response::new(AuthResponse {
            user: Some(user.into()),
            session: Some(session.into()),
        }))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let request = request.into_inner();

        EmptyResult::from(validators::username_format(request.username.as_str()))?;
        EmptyResult::from(validators::password(request.password.as_str()))?;

        let user = repos::user::read_by_username(request.username.as_str()).await?;
        if user.is_none() {
            return Err(Status::not_found("user_not_found"));
        }
        let mut user = user.unwrap();

        let request_password = Password::new(request.password.into(), String::default())?;
        let password =
            repos::password::read_active_by_user_id(user.get_id().full_identifier()).await?;
        if password.is_none() {
            return Err(Status::not_found("password_not_found"));
        }
        let password = password.unwrap();

        if !request_password.verify(&password)? {
            return Err(Status::permission_denied("invalid_password"));
        }

        if user.email.is_some() {
            user.email.as_mut().unwrap().decrypt().await?;
        }

        let session = Session::new(user.get_id().full_identifier().to_string());
        let session = repos::session::create(session).await?;
        user.sessions.push(Cow::Borrowed(session.get_id()));
        user.last_seen_on = Utc::now();
        repos::user::update(&user).await?;

        Ok(Response::new(AuthResponse {
            user: Some(user.into()),
            session: Some(session.into()),
        }))
    }

    async fn logout(
        &self,
        request: Request<protobuf::pandorica_auth::LogoutRequest>,
    ) -> Result<Response<protobuf::pandorica_auth::LogoutResponse>, Status> {
        let metadata = request.metadata();
        let mut session = get_session(metadata).await?;

        if session.verify() {
            session.expires_on = Utc::now();
            repos::session::update(&session).await?;
        }

        Ok(Response::new(protobuf::pandorica_auth::LogoutResponse {}))
    }
}
