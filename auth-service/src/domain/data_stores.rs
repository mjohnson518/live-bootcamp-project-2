use async_trait::async_trait;
use crate::domain::user::User;
use crate::domain::email::Email;
use crate::domain::password::Password;
use uuid::Uuid;  
use rand::Rng; 
use std::fmt;
use thiserror::Error;
use color_eyre::eyre::Report;

#[async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

#[derive(Debug, Error, PartialEq)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn store_token(&self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError,
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error, PartialEq)]
pub enum TwoFACodeStoreError {
    #[error("Login attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    // Parse a string into a LoginAttemptId, ensuring it's a valid UUID
    pub fn parse(id: String) -> Result<Self, String> {
        match Uuid::parse_str(&id) {
            Ok(_) => Ok(LoginAttemptId(id)),
            Err(_) => Err("Invalid login attempt ID format".to_string()),
        }
    }
}

impl Default for LoginAttemptId {
    // Generate a new random UUID when Default is called
    fn default() -> Self {
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}

// Implement AsRef<str> to easily get the underlying string
impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    // Parse a string into a TwoFACode, ensuring it's a 6-digit code
    pub fn parse(code: String) -> Result<Self, String> {
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err("2FA code must be exactly 6 digits".to_string());
        }
        Ok(TwoFACode(code))
    }
}

impl Default for TwoFACode {
    // Generate a new random 6-digit code when Default is called
    fn default() -> Self {
        let code = rand::thread_rng()
            .gen_range(0..=999999)
            .to_string()
            .pad_left(6, '0');
        TwoFACode(code)
    }
}

// Implement AsRef<str> to easily get the underlying string
impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// Helper trait to pad numbers with leading zeros
trait PadLeft {
    fn pad_left(self, width: usize, pad_char: char) -> String;
}

impl PadLeft for String {
    fn pad_left(self, width: usize, pad_char: char) -> String {
        let padding = if width > self.len() {
            width - self.len()
        } else {
            0
        };
        pad_char.to_string().repeat(padding) + &self
    }
}

impl fmt::Display for TwoFACode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}