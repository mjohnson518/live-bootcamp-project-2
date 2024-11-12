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
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip(self, user), fields(email = %user.email))]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        tracing::debug!("Computing password hash");
        let password_hash = compute_password_hash(user.password.as_ref())
            .map_err(|e| {
                tracing::error!("Failed to compute password hash: {:?}", e);
                UserStoreError::UnexpectedError
            })?;

        tracing::debug!("Inserting user into database");
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
                tracing::warn!("Attempted to insert duplicate user");
                UserStoreError::UserAlreadyExists
            } else {
                tracing::error!("Database error: {:?}", e);
                UserStoreError::UnexpectedError
            }
        })?;

        tracing::info!("Successfully added user to database");
        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip(self))]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        tracing::debug!("Querying database for user");
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
        .map_err(|e| {
            tracing::error!("Database error: {:?}", e);
            UserStoreError::UnexpectedError
        })?
        .ok_or_else(|| {
            tracing::debug!("User not found");
            UserStoreError::UserNotFound
        })?;

        tracing::debug!("Converting database record to User struct");
        Ok(User {
            email: Email::parse(user.email).map_err(|e| {
                tracing::error!("Failed to parse email: {:?}", e);
                UserStoreError::UnexpectedError
            })?,
            password: Password::parse(user.password_hash).map_err(|e| {
                tracing::error!("Failed to parse password: {:?}", e);
                UserStoreError::UnexpectedError
            })?,
            requires_2fa: user.requires_2fa,
        })
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip(self, password))]
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        tracing::debug!("Retrieving stored password hash");
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
        .map_err(|e| {
            tracing::error!("Database error: {:?}", e);
            UserStoreError::UnexpectedError
        })?
        .ok_or_else(|| {
            tracing::debug!("User not found during validation");
            UserStoreError::InvalidCredentials
        })?;

        tracing::debug!("Verifying password");
        verify_password_hash(&stored_user.password_hash, password.as_ref())
            .map_err(|e| {
                tracing::warn!("Password verification failed: {:?}", e);
                UserStoreError::InvalidCredentials
            })?;

        tracing::info!("User credentials validated successfully");
        Ok(())
    }
}

#[tracing::instrument(name = "Verifying password hash", skip(expected_password_hash, password_candidate))]
fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<(), Box<dyn Error>> {
    let expected_password_hash = PasswordHash::new(expected_password_hash)?;
    Argon2::default()
        .verify_password(password_candidate.as_bytes(), &expected_password_hash)
        .map_err(|e| e.into())
}

#[tracing::instrument(name = "Computing password hash", skip(password))]
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