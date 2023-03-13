use shared::error::{EmptyResult, OperationResult};

use crate::models::auth::Password;
use crate::DB;

pub async fn create(password: Password<'_>) -> OperationResult<Password> {
    let password: Password = DB.create("password").content(password).await?;
    Ok(password)
}

#[allow(dead_code)]
pub async fn read(id: &str) -> OperationResult<Option<Password>> {
    let password: Option<Password> = DB.select(("password", id)).await?;
    Ok(password)
}

pub async fn read_active_by_user_id(user_id: &str) -> OperationResult<Option<Password>> {
    let password: Option<Password> = DB
        .query(
            r#"
        SELECT *
        FROM password
        WHERE user_id = $user_id
        AND is_active = true
    "#,
        )
        .bind(("user_id", user_id))
        .await?
        .take(0)?;

    Ok(password)
}

#[allow(dead_code)]
pub async fn update(password: &Password<'_>) -> EmptyResult {
    if password.get_id().is_none() {
        return Err(anyhow::format_err!("Password ID is required").into());
    }

    DB.query(
        r#"
        UPDATE password
        SET user_id = $user_id,
            is_active = $is_active
        WHERE id = $id
    "#,
    )
    .bind(("user_id", &password.user_id))
    .bind(("is_active", password.is_active))
    .bind(("id", password.get_id().full_identifier()))
    .await?;

    Ok(())
}

#[allow(dead_code)]
pub async fn delete(id: &str) -> EmptyResult {
    DB.delete(("password", id)).await?;
    Ok(())
}
