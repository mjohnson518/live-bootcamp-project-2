use color_eyre::eyre::{Report, eyre};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    
    #[error("Missing token")]
    MissingToken,
    
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl AuthAPIError {
    pub fn unexpected<E: std::error::Error + Send + Sync + 'static>(error: E) -> Self {
        Self::UnexpectedError(Report::new(error))
    }

    pub fn unexpected_msg(msg: &str) -> Self {
        Self::UnexpectedError(eyre!(msg))
    }
}