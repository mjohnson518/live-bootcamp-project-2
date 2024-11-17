use std::sync::Arc;
use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use color_eyre::eyre::{Report, Context};
use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
#[tracing::instrument(name = "Redis 2FA code store", skip_all)]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Adding 2FA code", skip_all, fields(email = %email))]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        
        tracing::debug!("Creating 2FA tuple data");
        let data = TwoFATuple(
            login_attempt_id.as_ref().to_owned(),
            code.as_ref().to_owned(),
        );
        
        tracing::debug!("Serializing 2FA data");
        let serialized_data = serde_json::to_string(&data)
            .wrap_err("Failed to serialize 2FA tuple")
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

        tracing::debug!("Storing 2FA code in Redis");
        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&key, serialized_data, TEN_MINUTES_IN_SECONDS)
            .wrap_err("Failed to store 2FA code in Redis")
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

        tracing::info!("Successfully stored 2FA code");
        Ok(())
    }

    #[tracing::instrument(name = "Removing 2FA code", skip_all, fields(email = %email))]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);

        tracing::debug!("Removing 2FA code from Redis");
        let _: () = self
            .conn
            .write()
            .await
            .del(&key)
            .wrap_err("Failed to delete 2FA code from Redis")
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

        tracing::info!("Successfully removed 2FA code");
        Ok(())
    }

    #[tracing::instrument(name = "Getting 2FA code", skip_all, fields(email = %email))]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);

        tracing::debug!("Fetching 2FA code from Redis");
        match self.conn.write().await.get::<_, String>(&key) {
            Ok(value) => {
                tracing::debug!("Deserializing 2FA data");
                let data: TwoFATuple = serde_json::from_str(&value)
                    .wrap_err("Failed to deserialize 2FA tuple")
                    .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

                tracing::debug!("Parsing login attempt ID");
                let login_attempt_id = LoginAttemptId::parse(data.0)
                    .wrap_err("Failed to parse login attempt ID")
                    .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

                tracing::debug!("Parsing 2FA code");
                let email_code = TwoFACode::parse(data.1)
                    .wrap_err("Failed to parse 2FA code")
                    .map_err(|e| TwoFACodeStoreError::UnexpectedError(Report::new(e)))?;

                tracing::info!("Successfully retrieved 2FA code");
                Ok((login_attempt_id, email_code))
            }
            Err(e) => {
                tracing::warn!("Login attempt ID not found");
                Err(TwoFACodeStoreError::LoginAttemptIdNotFound)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

#[tracing::instrument(name = "Getting Redis key for email", skip_all, fields(email = %email))]
fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;

    async fn setup() -> RedisTwoFACodeStore {
        let client = Client::open("redis://127.0.0.1/").expect("Failed to create Redis client");
        let conn = client.get_connection().expect("Failed to get Redis connection");
        RedisTwoFACodeStore::new(Arc::new(RwLock::new(conn)))
    }

    #[tokio::test]
    async fn test_store_token() {
        let store = setup().await;
        let token = "test_token".to_string();
        
        assert!(store.store_token(token).await.is_ok());
    }

    #[tokio::test]
    async fn test_contains_token() {
        let store = setup().await;
        let token = "test_token".to_string();
        
        // Token should not exist initially
        assert!(!store.contains_token(&token).await.unwrap());
        
        // Store token
        store.store_token(token.clone()).await.unwrap();
        
        // Token should exist now
        assert!(store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let store = setup().await;
        let token1 = "test_token_1".to_string();
        let token2 = "test_token_2".to_string();
        
        // Store both tokens
        store.store_token(token1.clone()).await.unwrap();
        store.store_token(token2.clone()).await.unwrap();
        
        // Both tokens should exist
        assert!(store.contains_token(&token1).await.unwrap());
        assert!(store.contains_token(&token2).await.unwrap());
        
        // Non-existent token should not exist
        assert!(!store.contains_token("nonexistent").await.unwrap());
    }
}