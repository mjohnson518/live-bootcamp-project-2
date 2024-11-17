use std::collections::HashSet;
use std::sync::RwLock;
use async_trait::async_trait;
use color_eyre::eyre::eyre;
use secrecy::{ExposeSecret, Secret};
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
    async fn store_token(&self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        self.tokens
            .write()
            .map_err(|e| BannedTokenStoreError::UnexpectedError(eyre!(e).into()))
            .map(|mut tokens| {
                tokens.insert(token.expose_secret().to_string());
            })
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        self.tokens
            .read()
            .map_err(|e| BannedTokenStoreError::UnexpectedError(eyre!(e).into()))
            .map(|tokens| tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_token() {
        let store = HashsetBannedTokenStore::default();
        let token = Secret::new("test_token".to_string());
        
        assert!(store.store_token(token).await.is_ok());
    }

    #[tokio::test]
    async fn test_contains_token() {
        let store = HashsetBannedTokenStore::default();
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
        let store = HashsetBannedTokenStore::default();
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