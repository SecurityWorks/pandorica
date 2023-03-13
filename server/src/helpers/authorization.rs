use crate::models::auth::Session;
use crate::repos;
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

    Ok(session.unwrap())
}
