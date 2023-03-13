use once_cell::sync::Lazy;
use regex::Regex;
use shared::error::ValidationResult;

static PASSWORD_UPPER_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Z]+").unwrap());
static PASSWORD_LOWER_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"[a-z]+").unwrap());
static PASSWORD_DIGIT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"[0-9]+").unwrap());
static PASSWORD_SPECIAL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"[ !"$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]+"#).unwrap());

pub fn password(password: &str) -> ValidationResult {
    let mut errors: Vec<String> = Vec::new();

    if password.len() < 8_usize {
        errors.push("invalid_password__length".to_string());
    }

    if !PASSWORD_UPPER_REGEX.is_match(password) {
        errors.push("invalid_password__uppercase".to_string());
    }

    if !PASSWORD_LOWER_REGEX.is_match(password) {
        errors.push("invalid_password__lowercase".to_string());
    }

    if !PASSWORD_DIGIT_REGEX.is_match(password) {
        errors.push("invalid_password__digit".to_string());
    }

    if !PASSWORD_SPECIAL_REGEX.is_match(password) {
        errors.push("invalid_password__special".to_string());
    }

    ValidationResult(errors)
}
