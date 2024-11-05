use std::collections::HashMap;
use async_trait::async_trait;
use crate::domain::user::User;
use crate::domain::email::Email;
use crate::domain::password::Password;
use crate::domain::data_stores::{UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
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

    async fn get_user(&self, email: &Email) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) if user.password == *password => Ok(()),
            Some(_) => Err(UserStoreError::InvalidCredentials),
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let password = Password::parse("password123".to_string()).unwrap();
        let user = User::new(email.clone(), password, false);
        
        assert!(store.add_user(user.clone()).await.is_ok());
        assert_eq!(store.add_user(user).await, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let password = Password::parse("password123".to_string()).unwrap();
        let user = User::new(email.clone(), password, false);
        store.add_user(user.clone()).await.unwrap();
        
        assert_eq!(store.get_user(&email).await.map(|u| u.email.as_ref()), Ok("test@example.com"));
        let nonexistent_email = Email::parse("nonexistent@example.com".to_string()).unwrap();
        assert_eq!(store.get_user(&nonexistent_email).await, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let password = Password::parse("password123".to_string()).unwrap();
        let user = User::new(email.clone(), password.clone(), false);
        store.add_user(user).await.unwrap();
        
        assert!(store.validate_user(&email, &password).await.is_ok());
        let wrong_password = Password::parse("wrongpassword".to_string()).unwrap();
        assert_eq!(store.validate_user(&email, &wrong_password).await, Err(UserStoreError::InvalidCredentials));
        let nonexistent_email = Email::parse("nonexistent@example.com".to_string()).unwrap();
        assert_eq!(store.validate_user(&nonexistent_email, &password).await, Err(UserStoreError::UserNotFound));
    }
}