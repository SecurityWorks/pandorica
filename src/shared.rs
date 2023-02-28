use std::fmt::{Display, Formatter};
use tonic::Status;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    content: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl Error {
    pub fn new<T>(content: T) -> Self
    where
        T: std::error::Error + Send + Sync + 'static,
    {
        Error {
            content: Box::new(content),
        }
    }

    pub fn new_from(content: &str) -> Self {
        Error {
            content: Box::new(std::io::Error::new(std::io::ErrorKind::Other, content)),
        }
    }

    pub fn empty() -> Self {
        Error {
            content: Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Undefined error",
            )),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content)
    }
}

impl<T> From<T> for Error
where
    T: std::error::Error + Send + Sync + 'static,
{
    fn from(value: T) -> Self {
        Self {
            content: Box::new(value),
        }
    }
}

impl From<Error> for Status {
    fn from(value: Error) -> Self {
        Status::internal(value.content.to_string())
    }
}

impl From<Error> for Box<dyn std::error::Error + Send + Sync + 'static> {
    fn from(value: Error) -> Self {
        value.content
    }
}

#[macro_export]
macro_rules! throw_error {
    () => {{
        tracing::error!("Unexpected error");
        panic!()
    }};
    ($message: tt) => {{
        tracing::error!($message);
        panic!()
    }};
    ($format:tt, $($arg:tt)*) => {{
        tracing::error!($format, $($arg)*);
        panic!()
    }};
}
