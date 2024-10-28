use std::collections::HashMap;
use async_trait::async_trait;
use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

/// A simple in-memory implementation of TwoFACodeStore using HashMap
#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    // The HashMap stores Email as key and a tuple of (LoginAttemptId, TwoFACode) as value
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    /// Add a new 2FA code for a user
    /// If a code already exists for this email, it will be replaced
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        // Insert the new code into the HashMap
        // Using insert() will automatically replace any existing value
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    /// Remove a 2FA code for a user
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        // Remove the code from the HashMap
        // If the email doesn't exist, we still return Ok since the end result is the same
        self.codes.remove(email);
        Ok(())
    }

    /// Get the stored 2FA code and login attempt ID for a user
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        // Try to get the code from the HashMap
        // If it doesn't exist, return an error
        self.codes
            .get(email)
            .map(|(id, code)| (id.clone(), code.clone()))
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_store_and_retrieve_code() {
        // Create a new store
        let mut store = HashmapTwoFACodeStore::default();
        
        // Create test data
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();

        // Store the code
        store.add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .expect("Failed to store code");

        // Retrieve the code
        let (stored_id, stored_code) = store.get_code(&email)
            .await
            .expect("Failed to retrieve code");

        // Verify the stored values match what we put in
        assert_eq!(stored_id, login_attempt_id);
        assert_eq!(stored_code, code);
    }

    #[tokio::test]
    async fn should_return_error_for_nonexistent_email() {
        // Create a new store
        let store = HashmapTwoFACodeStore::default();
        
        // Try to retrieve a code for an email that doesn't exist
        let email = Email::parse("nonexistent@example.com".to_string()).unwrap();
        let result = store.get_code(&email).await;

        // Verify we get the expected error
        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn should_remove_existing_code() {
        // Create a new store
        let mut store = HashmapTwoFACodeStore::default();
        
        // Create and store test data
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();

        store.add_code(email.clone(), login_attempt_id, code)
            .await
            .expect("Failed to store code");

        // Remove the code
        store.remove_code(&email)
            .await
            .expect("Failed to remove code");

        // Try to retrieve the removed code
        let result = store.get_code(&email).await;

        // Verify the code was removed
        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn should_update_existing_code() {
        // Create a new store
        let mut store = HashmapTwoFACodeStore::default();
        
        // Create initial test data
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let initial_id = LoginAttemptId::default();
        let initial_code = TwoFACode::parse("123456".to_string()).unwrap();

        // Store initial code
        store.add_code(email.clone(), initial_id, initial_code)
            .await
            .expect("Failed to store initial code");

        // Create new test data
        let new_id = LoginAttemptId::default();
        let new_code = TwoFACode::parse("654321".to_string()).unwrap();

        // Update with new code
        store.add_code(email.clone(), new_id.clone(), new_code.clone())
            .await
            .expect("Failed to update code");

        // Retrieve the code
        let (stored_id, stored_code) = store.get_code(&email)
            .await
            .expect("Failed to retrieve updated code");

        // Verify the stored values match the new values
        assert_eq!(stored_id, new_id);
        assert_eq!(stored_code, new_code);
    }
}