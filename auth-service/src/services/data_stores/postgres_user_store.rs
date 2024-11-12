use color_eyre::eyre::{eyre, Context, Result};
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
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(user.password.as_ref().to_owned())
            .await
            .map_err(UserStoreError::UnexpectedError)?;

        sqlx::query!(
            r#"
            INSERT INTO users (email, password_hash, requires_2fa)
            VALUES ($1, $2, $3)
            "#,
            user.email.as_ref(),
            &password_hash,
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
                UserStoreError::UnexpectedError(e.into())
            }
        })?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let user = sqlx::query!(
            r#"
            SELECT email, password_hash, requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?
        .ok_or(UserStoreError::UserNotFound)?;

        Ok(User {
            email: Email::parse(user.email)
                .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?,
            password: Password::parse(user.password_hash)
                .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?,
            requires_2fa: user.requires_2fa,
        })
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
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
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?
        .ok_or(UserStoreError::InvalidCredentials)?;

        verify_password_hash(&stored_user.password_hash, password.as_ref().to_string())
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        Ok(())
    }
}

#[tracing::instrument(name = "Verifying password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<()> {
    let current_span: tracing::Span = tracing::Span::current();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let expected_password_hash: PasswordHash<'_> =
                PasswordHash::new(&expected_password_hash)?;

            Argon2::default()
                .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                .wrap_err("failed to verify password hash")
        })
    })
    .await;

    result?
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: String) -> Result<String> {
    let current_span: tracing::Span = tracing::Span::current();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(password_hash)
        })
    })
    .await;

    result?
}