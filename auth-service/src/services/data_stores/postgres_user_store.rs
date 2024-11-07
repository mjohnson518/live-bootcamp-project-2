use std::error::Error;
use argon2::{
    password_hash::SaltString, 
    Algorithm, 
    Argon2, 
    Params, 
    PasswordHash, 
    PasswordHasher,
    PasswordVerifier, 
    Version,
};
use sqlx::PgPool;
use async_trait::async_trait;
use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    email::Email,
    password::Password,
    user::User,
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Hash the password before storing
        let password_hash = compute_password_hash(user.password.as_ref())
            .map_err(|_| UserStoreError::UnexpectedError)?;

        // Insert the user into the database
        sqlx::query!(
            r#"
            INSERT INTO users (email, password_hash, requires_2fa)
            VALUES ($1, $2, $3)
            "#,
            user.email.as_ref(),
            password_hash,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .and_then(|e| e.constraint())
                .unwrap_or_default()
                == "users_pkey"
            {
                UserStoreError::UserAlreadyExists
            } else {
                UserStoreError::UnexpectedError
            }
        })?;

        Ok(())
    }

    // Change the return type to owned User instead of reference
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let user = sqlx::query!(
            r#"
            SELECT email, password_hash as "password_hash!", requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?
        .ok_or(UserStoreError::UserNotFound)?;

        // Convert database record to User struct
        Ok(User {
            email: Email::parse(user.email).map_err(|_| UserStoreError::UnexpectedError)?,
            password: Password::parse(user.password_hash).map_err(|_| UserStoreError::UnexpectedError)?,
            requires_2fa: user.requires_2fa,
        })
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        let stored_user = sqlx::query!(
            r#"
            SELECT password_hash
            FROM users
            WHERE email = $1
            "#,
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?
        .ok_or(UserStoreError::InvalidCredentials)?;

        // Verify the password matches
        verify_password_hash(&stored_user.password_hash, password.as_ref())
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        Ok(())
    }
}

/// Helper function to verify if a given password matches an expected hash
fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<(), Box<dyn Error>> {
    let expected_password_hash = PasswordHash::new(expected_password_hash)?;
    Argon2::default()
        .verify_password(password_candidate.as_bytes(), &expected_password_hash)
        .map_err(|e| e.into())
}

/// Helper function to hash passwords before persisting them in the database
fn compute_password_hash(password: &str) -> Result<String, Box<dyn Error>> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None)?,
    )
    .hash_password(password.as_bytes(), &salt)?
    .to_string();

    Ok(password_hash)
}