use crate::models::crypto::Mk;
use crate::{EmptyResult, DB};
use shared::error::OperationResult;
use surrealdb::opt::PatchOp;

pub async fn create(mk: Mk<'_>) -> OperationResult<Mk> {
    let mk: Mk = DB.create("master_key").content(mk).await?;
    Ok(mk)
}

pub async fn read<'a>(id: &str) -> OperationResult<Option<Mk<'a>>> {
    let mk: Option<Mk> = DB.select(("master_key", id)).await?;
    Ok(mk)
}

pub async fn read_current<'a>() -> OperationResult<Option<Mk<'a>>> {
    let mut result = DB
        .query(
            r#"
            SELECT *
            FROM master_key
            WHERE is_active = true
        "#,
        )
        .await?;

    let mk: Option<Mk> = result.take(0)?;

    Ok(mk)
}

pub async fn update(mk: &Mk<'_>) -> EmptyResult {
    if mk.get_id().is_none() {
        return Err(anyhow::format_err!("Password ID is required").into());
    }

    DB.update(("master_key", mk.get_id().partial_identifier()))
        .patch(PatchOp::replace("/expires_on", mk.expires_on))
        .patch(PatchOp::replace("/is_active", mk.is_active))
        .await?;

    Ok(())
}

#[allow(dead_code)]
pub async fn delete(id: &str) -> EmptyResult {
    DB.delete(("master_key", id)).await?;
    Ok(())
}
