use std::fmt::{Display, Formatter};
use tonic::Status;

#[derive(Debug)]
pub struct Error(anyhow::Error);

#[derive(Debug)]
pub struct ValidationResult(pub Vec<String>);

pub type OperationResult<T> = Result<T, Error>;
pub type EmptyResult = Result<(), Error>;

impl<T: Into<anyhow::Error>> From<T> for Error {
    fn from(value: T) -> Self {
        Error(value.into())
    }
}

impl From<Error> for Status {
    fn from(value: Error) -> Self {
        Status::internal(value.0.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ValidationResult> for EmptyResult {
    fn from(value: ValidationResult) -> Self {
        if value.0.is_empty() {
            Ok(())
        } else {
            Err(Error(anyhow::anyhow!(value.0.join(", "))))
        }
    }
}
