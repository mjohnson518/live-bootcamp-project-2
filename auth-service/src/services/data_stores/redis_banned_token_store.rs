use std::sync::Arc;
use redis::{Commands, Connection};
use tokio::sync::RwLock;
use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn store_token(&self, token: String) -> Result<(), BannedTokenStoreError> {
        let token_key = get_key(token.as_str());
        
        let value = true;
        let ttl: u64 = TOKEN_TTL_SECONDS
            .try_into()
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&token_key, value, ttl)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let token_key = get_key(token);

        let is_banned: bool = self
            .conn
            .write()
            .await
            .exists(&token_key)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(is_banned)
    }
}

const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;

    async fn setup() -> RedisBannedTokenStore {
        let client = Client::open("redis://127.0.0.1/").expect("Failed to create Redis client");
        let conn = client.get_connection().expect("Failed to get Redis connection");
        RedisBannedTokenStore::new(Arc::new(RwLock::new(conn)))
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