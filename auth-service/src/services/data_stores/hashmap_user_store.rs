use std::collections::HashMap;
use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    email::Email,
    password::Password,
    user::User,
};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

#[async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let email = user.email.as_ref().expose_secret().to_string();
        if self.users.contains_key(&email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(email, user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email.as_ref().expose_secret())
            .cloned()  // Clone the user to return ownership
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        match self.users.get(email.as_ref().expose_secret()) {
            Some(user) if user.password.as_ref().expose_secret() == password.as_ref().expose_secret() => Ok(()),
            _ => Err(UserStoreError::InvalidCredentials),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let password = Password::parse(Secret::new("password123".to_string())).unwrap();
        let user = User::new(email.clone(), password, false);
        
        assert!(store.add_user(user.clone()).await.is_ok());
        assert_eq!(store.add_user(user).await, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let password = Password::parse(Secret::new("password123".to_string())).unwrap();
        let user = User::new(email.clone(), password, false);
        store.add_user(user.clone()).await.unwrap();
        
        let retrieved_user = store.get_user(&email).await.unwrap();
        assert_eq!(retrieved_user.email.as_ref().expose_secret(), "test@example.com");
        
        let nonexistent_email = Email::parse(Secret::new("nonexistent@example.com".to_string())).unwrap();
        assert_eq!(store.get_user(&nonexistent_email).await, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let password = Password::parse(Secret::new("password123".to_string())).unwrap();
        let user = User::new(email.clone(), password.clone(), false);
        store.add_user(user).await.unwrap();
        
        assert!(store.validate_user(&email, &password).await.is_ok());
        let wrong_password = Password::parse(Secret::new("wrongpassword".to_string())).unwrap();
        assert_eq!(store.validate_user(&email, &wrong_password).await, Err(UserStoreError::InvalidCredentials));
        let nonexistent_email = Email::parse(Secret::new("nonexistent@example.com".to_string())).unwrap();
        assert_eq!(store.validate_user(&nonexistent_email, &password).await, Err(UserStoreError::InvalidCredentials));
    }
}