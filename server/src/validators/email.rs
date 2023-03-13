use shared::error::ValidationResult;

pub fn email(email: Option<&String>) -> ValidationResult {
    let mut errors = Vec::new();

    if let Some(e) = email {
        if !validator::validate_email(e) {
            errors.push("invalid_user__email".to_string());
        }
    }

    ValidationResult(errors)
}
