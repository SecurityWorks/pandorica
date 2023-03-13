use crate::models::auth::Session;
use crate::repos;
use chrono::Utc;
use tonic::metadata::MetadataMap;
use tonic::Status;

pub async fn get_session(metadata: &MetadataMap) -> Result<Session, Status> {
    let metadata = metadata.get("session_id");
    if metadata.is_none() {
        return Err(Status::unauthenticated("No session_id provided"));
    }

    let session_id = metadata.unwrap().to_str();
    if session_id.is_err() {
        return Err(Status::unauthenticated("Invalid session_id provided"));
    }
    let session_id = session_id.unwrap();

    let session = repos::session::read(session_id).await?;
    if session.is_none() {
        return Err(Status::unauthenticated("Invalid session_id provided"));
    }
    let mut session = session.unwrap();

    let user = repos::user::read(session.user_id.split(':').last().unwrap()).await?;
    if user.is_none() {
        return Err(Status::unauthenticated("User not found"));
    }
    let mut user = user.unwrap();

    session.last_used_on = Utc::now();
    repos::session::update(&session).await?;

    user.last_seen_on = Utc::now();
    repos::user::update(&user).await?;

    Ok(session)
}
