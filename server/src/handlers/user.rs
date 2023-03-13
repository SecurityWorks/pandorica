use crate::helpers::authorization::get_session;
use crate::repos;
use async_trait::async_trait;
use protobuf::pandorica_common;
use protobuf::pandorica_user::{user_service_server, MeRequest, MeResponse};
use tonic::{Request, Response, Status};

#[derive(Default)]
pub struct UserService {}

#[async_trait]
impl user_service_server::UserService for UserService {
    async fn me(&self, request: Request<MeRequest>) -> Result<Response<MeResponse>, Status> {
        let metadata = request.metadata();
        let session = get_session(metadata).await?;

        let user = repos::user::read(session.user_id.split(':').last().unwrap()).await?;
        if user.is_none() {
            return Err(Status::unauthenticated("User not found"));
        }
        let mut user = user.unwrap();
        if !user.is_active {
            return Err(Status::unauthenticated("User is inactive"));
        }
        if user.email.is_some() {
            user.email.as_mut().unwrap().decrypt().await?;
        }

        let session = repos::session::read(session.get_id().partial_identifier()).await?;
        if session.is_none() {
            return Err(Status::unauthenticated("Session not found"));
        }
        let session = session.unwrap();
        if !session.verify() {
            return Err(Status::unauthenticated("Session expired"));
        }

        let sessions = repos::session::read_all_by_user_id(user.get_id().full_identifier()).await?;
        let mut parsed_sessions: Vec<pandorica_common::Session> = Vec::new();
        for session in sessions {
            parsed_sessions.push(session.into());
        }

        Ok(Response::new(MeResponse {
            user: Some(user.into()),
            sessions: parsed_sessions,
        }))
    }
}
