use std::collections::HashMap;
use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    // The HashMap stores Email as key and a tuple of (LoginAttemptId, TwoFACode) as value
    codes: HashMap<String, (LoginAttemptId, TwoFACode)>,
}

#[async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email.as_ref().expose_secret().to_string(), (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email.as_ref().expose_secret());
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes
            .get(email.as_ref().expose_secret())
            .map(|(id, code)| (id.clone(), code.clone()))
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_store_and_retrieve_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse(Secret::new("123456".to_string())).unwrap();

        store.add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .expect("Failed to store code");

        let (stored_id, stored_code) = store.get_code(&email)
            .await
            .expect("Failed to retrieve code");

        assert_eq!(stored_id, login_attempt_id);
        assert_eq!(stored_code, code);
    }

    #[tokio::test]
    async fn should_return_error_for_nonexistent_email() {
        let store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("nonexistent@example.com".to_string())).unwrap();
        let result = store.get_code(&email).await;

        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn should_remove_existing_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse(Secret::new("123456".to_string())).unwrap();

        store.add_code(email.clone(), login_attempt_id, code)
            .await
            .expect("Failed to store code");

        store.remove_code(&email)
            .await
            .expect("Failed to remove code");

        let result = store.get_code(&email).await;

        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn should_update_existing_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("test@example.com".to_string())).unwrap();
        let initial_id = LoginAttemptId::default();
        let initial_code = TwoFACode::parse(Secret::new("123456".to_string())).unwrap();

        store.add_code(email.clone(), initial_id, initial_code)
            .await
            .expect("Failed to store initial code");

        let new_id = LoginAttemptId::default();
        let new_code = TwoFACode::parse(Secret::new("654321".to_string())).unwrap();

        store.add_code(email.clone(), new_id.clone(), new_code.clone())
            .await
            .expect("Failed to update code");

        let (stored_id, stored_code) = store.get_code(&email)
            .await
            .expect("Failed to retrieve updated code");

        assert_eq!(stored_id, new_id);
        assert_eq!(stored_code, new_code);
    }
}