use once_cell::sync::Lazy;
use regex::Regex;
use shared::error::ValidationResult;

use crate::models::auth::Password;

static PASSWORD_UPPER_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Z]+").unwrap());
static PASSWORD_LOWER_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"[a-z]+").unwrap());
static PASSWORD_DIGIT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"[0-9]+").unwrap());
static PASSWORD_SPECIAL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"[ !"$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]+"#).unwrap());

pub fn password(password: &Password<'_>) -> ValidationResult {
    let mut errors: Vec<String> = Vec::new();

    if let Some(p) = &password.plaintext {
        errors = p.exposed_in_as_zstr(|p| {
            let mut errors = Vec::new();

            if p.len() < 8_usize {
                errors.push("invalid_password__length".to_string());
            }

            if !PASSWORD_UPPER_REGEX.is_match(&p) {
                errors.push("invalid_password__uppercase".to_string());
            }

            if !PASSWORD_LOWER_REGEX.is_match(&p) {
                errors.push("invalid_password__lowercase".to_string());
            }

            if !PASSWORD_DIGIT_REGEX.is_match(&p) {
                errors.push("invalid_password__digit".to_string());
            }

            if !PASSWORD_SPECIAL_REGEX.is_match(&p) {
                errors.push("invalid_password__special".to_string());
            }

            errors
        });
    }

    ValidationResult(errors)
}
