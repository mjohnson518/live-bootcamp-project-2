use std::collections::HashSet;
use std::sync::RwLock;
use async_trait::async_trait;
use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: RwLock<HashSet<String>>,
}

impl HashsetBannedTokenStore {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn store_token(&self, token: String) -> Result<(), BannedTokenStoreError> {
        match self.tokens.write() {
            Ok(mut tokens) => {
                tokens.insert(token);
                Ok(())
            }
            Err(_) => Err(BannedTokenStoreError::UnexpectedError),
        }
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        match self.tokens.read() {
            Ok(tokens) => Ok(tokens.contains(token)),
            Err(_) => Err(BannedTokenStoreError::UnexpectedError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_token() {
        let store = HashsetBannedTokenStore::default();
        let token = "test_token".to_string();
        
        assert!(store.store_token(token).await.is_ok());
    }

    #[tokio::test]
    async fn test_contains_token() {
        let store = HashsetBannedTokenStore::default();
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
        let store = HashsetBannedTokenStore::default();
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