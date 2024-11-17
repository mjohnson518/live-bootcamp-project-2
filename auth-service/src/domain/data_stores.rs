use async_trait::async_trait;
use crate::domain::user::User;
use crate::domain::email::Email;
use crate::domain::password::Password;
use uuid::Uuid;  
use rand::Rng; 
use std::fmt;
use thiserror::Error;
use color_eyre::eyre::Report;
use secrecy::{ExposeSecret, Secret};

#[async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

#[derive(Debug, Error)]
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

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
            | (Self::UserNotFound, Self::UserNotFound)
            | (Self::InvalidCredentials, Self::InvalidCredentials)
            | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn store_token(&self, token: Secret<String>) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
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

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
            | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(Secret<String>);

impl LoginAttemptId {
    pub fn parse(id: Secret<String>) -> Result<Self, String> {
        match Uuid::parse_str(id.expose_secret()) {
            Ok(_) => Ok(LoginAttemptId(id)),
            Err(_) => Err("Invalid login attempt ID format".to_string()),
        }
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Secret::new(Uuid::new_v4().to_string()))
    }
}

impl AsRef<Secret<String>> for LoginAttemptId {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(Secret<String>);

impl TwoFACode {
    pub fn parse(code: Secret<String>) -> Result<Self, String> {
        if code.expose_secret().len() != 6 || !code.expose_secret().chars().all(|c| c.is_ascii_digit()) {
            return Err("2FA code must be exactly 6 digits".to_string());
        }
        Ok(TwoFACode(code))
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let code = rand::thread_rng()
            .gen_range(0..=999999)
            .to_string()
            .pad_left(6, '0');
        TwoFACode(Secret::new(code))
    }
}

impl AsRef<Secret<String>> for TwoFACode {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

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
        write!(f, "{}", self.0.expose_secret())
    }
}