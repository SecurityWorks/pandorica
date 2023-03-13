use shared::error::{EmptyResult, OperationResult};

use crate::models::auth::Session;
use crate::DB;

pub async fn create(session: Session<'_>) -> OperationResult<Session> {
    let session: Session = DB.create("session").content(session).await?;
    Ok(session)
}

pub async fn read(id: &str) -> OperationResult<Option<Session>> {
    let session: Option<Session> = DB.select(("session", id)).await?;
    Ok(session)
}

pub async fn read_all_by_user_id(user_id: &str) -> OperationResult<Vec<Session>> {
    let sessions: Vec<Session> = DB
        .query(
            r#"
    SELECT *
    FROM session
    WHERE user_id = $user_id
    "#,
        )
        .bind(("user_id", user_id))
        .await?
        .take(0)?;

    Ok(sessions)
}

pub async fn update(session: &Session<'_>) -> EmptyResult {
    if session.get_id().is_none() {
        return Err(anyhow::format_err!("Session ID is required").into());
    }

    DB.query(
        r#"
    UPDATE session
    SET user_id = $user_id,
        last_used_on = $last_used_on,
        expires_on = $expires_on
    WHERE id = $id
    "#,
    )
    .bind(("user_id", &session.user_id))
    .bind(("last_used_on", session.last_used_on))
    .bind(("expires_on", session.expires_on))
    .bind(("id", session.get_id().full_identifier()))
    .await?;

    Ok(())
}

#[allow(dead_code)]
pub async fn delete(id: &str) -> EmptyResult {
    DB.delete(("session", id)).await?;
    Ok(())
}
