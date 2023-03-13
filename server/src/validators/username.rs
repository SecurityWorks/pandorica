use once_cell::sync::Lazy;
use regex::Regex;
use shared::error::ValidationResult;

use crate::repos;

static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.]{3,32}$").unwrap());

pub fn username_format(username: &str) -> ValidationResult {
    let mut errors = Vec::new();

    if !USERNAME_REGEX.is_match(username) {
        errors.push("invalid_user__username".to_string());
    }

    ValidationResult(errors)
}

pub async fn username_duplicate(username: &str) -> ValidationResult {
    let mut errors = Vec::new();

    let user = repos::user::read_by_username(username)
        .await
        .map_err(|e| errors.push(e.to_string()));
    if let Ok(user) = user {
        if user.is_some() {
            errors.push("duplicate_user__username".to_string());
        }
    }

    ValidationResult(errors)
}
