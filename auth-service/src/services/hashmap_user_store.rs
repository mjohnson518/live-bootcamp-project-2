use std::collections::HashMap;
use async_trait::async_trait;
use crate::domain::user::User;
use crate::domain::data_stores::{UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

#[async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) if user.password == password => Ok(()),
            Some(_) => Err(UserStoreError::InvalidCredentials),
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), false);
        
        assert!(store.add_user(user.clone()).await.is_ok());
        assert_eq!(store.add_user(user).await, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), false);
        store.add_user(user.clone()).await.unwrap();
        
        assert_eq!(store.get_user("test@example.com").await.map(|u| u.email.as_str()), Ok("test@example.com"));
        assert_eq!(store.get_user("nonexistent@example.com").await, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), false);
        store.add_user(user).await.unwrap();
        
        assert!(store.validate_user("test@example.com", "password123").await.is_ok());
        assert_eq!(store.validate_user("test@example.com", "wrongpassword").await, Err(UserStoreError::InvalidCredentials));
        assert_eq!(store.validate_user("nonexistent@example.com", "password123").await, Err(UserStoreError::UserNotFound));
    }
}