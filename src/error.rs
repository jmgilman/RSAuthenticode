use thiserror::Error;

#[derive(Error, Debug)]
pub enum APIError {
    #[error("The authenticode validation failed!")]
    ValidationFailed,
}
