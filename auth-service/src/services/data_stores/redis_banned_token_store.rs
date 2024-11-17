use std::sync::Arc;
use redis::{Commands, Connection};
use tokio::sync::RwLock;
use color_eyre::eyre::{Report, Context};
use secrecy::{ExposeSecret, Secret};
use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreError};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
#[tracing::instrument(name = "Redis banned token store", skip_all)]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn store_token(&self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        tracing::debug!("Storing banned token in Redis");
        let _: () = self
            .conn
            .write()
            .await
            .set(token.expose_secret(), true)
            .wrap_err("Failed to store banned token in Redis")
            .map_err(|e| BannedTokenStoreError::UnexpectedError(Report::new(e)))?;

        tracing::info!("Successfully stored banned token");
        Ok(())
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        tracing::debug!("Checking if token is banned in Redis");
        let result: bool = self
            .conn
            .write()
            .await
            .exists(token.expose_secret())
            .wrap_err("Failed to check token in Redis")
            .map_err(|e| BannedTokenStoreError::UnexpectedError(Report::new(e)))?;

        tracing::debug!("Token ban status checked successfully");
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;
    use secrecy::Secret;

    async fn setup() -> RedisBannedTokenStore {
        let client = Client::open("redis://127.0.0.1/").expect("Failed to create Redis client");
        let conn = client.get_connection().expect("Failed to get Redis connection");
        RedisBannedTokenStore::new(Arc::new(RwLock::new(conn)))
    }

    #[tokio::test]
    async fn test_store_token() {
        let store = setup().await;
        let token = Secret::new("test_token".to_string());
        
        assert!(store.store_token(token).await.is_ok());
    }

    #[tokio::test]
    async fn test_contains_token() {
        let store = setup().await;
        let token = Secret::new("test_token".to_string());
        
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
        let token1 = Secret::new("test_token_1".to_string());
        let token2 = Secret::new("test_token_2".to_string());
        
        // Store both tokens
        store.store_token(token1.clone()).await.unwrap();
        store.store_token(token2.clone()).await.unwrap();
        
        // Both tokens should exist
        assert!(store.contains_token(&token1).await.unwrap());
        assert!(store.contains_token(&token2).await.unwrap());
        
        // Non-existent token should not exist
        assert!(!store.contains_token(&Secret::new("nonexistent".to_string())).await.unwrap());
    }
}