use crate::models::auth::User;
use crate::DB;
use shared::error::{EmptyResult, OperationResult};

pub async fn create(user: User<'_>) -> OperationResult<User> {
    let user: User = DB.create("user").content(user).await?;
    Ok(user)
}

#[allow(dead_code)]
pub async fn read(id: &str) -> OperationResult<Option<User>> {
    let user: Option<User> = DB.select(("user", id)).await?;
    Ok(user)
}

pub async fn read_by_username(username: &str) -> OperationResult<Option<User>> {
    let mut result = DB
        .query(
            r#"
        SELECT *
        FROM user
        WHERE username = $username
    "#,
        )
        .bind(("username", username))
        .await?;

    let user: Option<User> = result.take(0)?;
    Ok(user)
}

pub async fn update(user: &User<'_>) -> EmptyResult {
    if user.get_id().is_none() {
        return Err(anyhow::format_err!("User ID is required").into());
    }

    DB.query(
        r#"
    UPDATE user
    SET passwords = $passwords,
        sessions = $sessions,
        last_seen_on = $last_seen_on,
        is_active = $is_active
    WHERE id = $id
    "#,
    )
    .bind(("passwords", &user.passwords))
    .bind(("sessions", &user.sessions))
    .bind(("last_seen_on", user.last_seen_on))
    .bind(("is_active", user.is_active))
    .bind(("id", user.get_id().full_identifier()))
    .await?;

    Ok(())
}

#[allow(dead_code)]
pub async fn delete(id: &str) -> EmptyResult {
    // TODO: Also delete all passwords associated with this user
    DB.delete(("user", id)).await?;
    Ok(())
}
