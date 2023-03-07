use shared::error::{EmptyResult, OperationResult};
use surrealdb::opt::PatchOp;

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

#[allow(dead_code)]
pub async fn update(password: &Password<'_>) -> EmptyResult {
    if password.get_id().is_none() {
        return Err(anyhow::format_err!("Password ID is required").into());
    }

    DB.update(("password", password.get_id().partial_identifier()))
        .patch(PatchOp::replace("/is_active", password.is_active))
        .await?;

    Ok(())
}

#[allow(dead_code)]
pub async fn delete(id: &str) -> EmptyResult {
    DB.delete(("password", id)).await?;
    Ok(())
}
