use crate::models::auth::User;
use crate::{repos, DB};
use shared::error::{EmptyResult, OperationResult};

pub async fn create(mut user: User<'_>) -> OperationResult<User> {
    user.password = repos::password::create(user.password.value().unwrap().clone())
        .await?
        .into();
    let user: User = DB.create("user").content(user).await?;
    Ok(user)
}

#[allow(dead_code)]
pub async fn read(id: &str) -> OperationResult<Option<User>> {
    let mut result = DB
        .query(
            r#"
        SELECT *
        FROM user
        WHERE id = $id
        FETCH password, historical_passwords
    "#,
        )
        .bind(("id", id))
        .await?;

    let user: Option<User> = result.take(0)?;

    Ok(user)
}

pub async fn read_by_username(username: &str) -> OperationResult<Option<User>> {
    let mut result = DB
        .query(
            r#"
        SELECT *
        FROM user
        WHERE username = $username
        FETCH password, historical_passwords
    "#,
        )
        .bind(("username", username))
        .await?;

    let user: Option<User> = result.take(0)?;

    Ok(user)
}

#[allow(dead_code)]
pub async fn update(_user: &User<'_>) -> EmptyResult {
    todo!()
}

#[allow(dead_code)]
pub async fn delete(id: &str) -> EmptyResult {
    // TODO: Also delete all passwords associated with this user
    DB.delete(("user", id)).await?;
    Ok(())
}
