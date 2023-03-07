use once_cell::sync::Lazy;
use regex::Regex;
use shared::error::ValidationResult;

use crate::models::auth::User;
use crate::{repos, validators};

static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.]{3,32}$").unwrap());

pub async fn user(user: &User<'_>) -> ValidationResult {
    let mut errors = Vec::new();

    if !USERNAME_REGEX.is_match(&user.username) {
        errors.push("invalid_user__username".to_string());
    }

    if let Some(e) = &user.email {
        if e.value()
            .unwrap()
            .exposed_in_as_zstr(|email| !validator::validate_email(email.as_str()))
        {
            errors.push("invalid_user__email".to_string());
        }
    }

    errors.extend(validators::password(user.password.value().unwrap()).0);

    ValidationResult(errors)
}

pub async fn user_duplicate(user: &User<'_>) -> ValidationResult {
    let mut errors = Vec::new();

    let user = repos::user::read_by_username(&user.username)
        .await
        .map_err(|e| errors.push(e.to_string()));
    if let Ok(user) = user {
        if user.is_some() {
            errors.push("duplicate_user__username".to_string());
        }
    }

    ValidationResult(errors)
}
