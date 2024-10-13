use std::collections::HashMap;
use crate::domain::user::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }

    pub fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
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

    #[test]
    fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), false);
        
        assert!(store.add_user(user.clone()).is_ok());
        assert_eq!(store.add_user(user), Err(UserStoreError::UserAlreadyExists));
    }

    #[test]
    fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), false);
        store.add_user(user.clone()).unwrap();
        
        assert_eq!(store.get_user("test@example.com"), Ok(&user));
        assert_eq!(store.get_user("nonexistent@example.com"), Err(UserStoreError::UserNotFound));
    }

    #[test]
    fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), false);
        store.add_user(user).unwrap();
        
        assert!(store.validate_user("test@example.com", "password123").is_ok());
        assert_eq!(store.validate_user("test@example.com", "wrongpassword"), Err(UserStoreError::InvalidCredentials));
        assert_eq!(store.validate_user("nonexistent@example.com", "password123"), Err(UserStoreError::UserNotFound));
    }
}