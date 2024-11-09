use std::sync::Arc;
use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        
        let data = TwoFATuple(
            login_attempt_id.as_ref().to_owned(),
            code.as_ref().to_owned(),
        );
        let serialized_data = 
            serde_json::to_string(&data).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&key, serialized_data, TEN_MINUTES_IN_SECONDS)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);

        let _: () = self
            .conn
            .write()
            .await
            .del(&key)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);

        match self.conn.write().await.get::<_, String>(&key) {
            Ok(value) => {
                let data: TwoFATuple = serde_json::from_str(&value)
                    .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

                let login_attempt_id = LoginAttemptId::parse(data.0)
                    .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

                let email_code = 
                    TwoFACode::parse(data.1).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

                Ok((login_attempt_id, email_code))
            }
            Err(_) => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Client;

    async fn setup() -> RedisTwoFACodeStore {
        let client = Client::open("redis://127.0.0.1/").expect("Failed to create Redis client");
        let conn = client.get_connection().expect("Failed to get Redis connection");
        RedisTwoFACodeStore::new(Arc::new(RwLock::new(conn)))
    }

    #[tokio::test]
    async fn should_store_and_retrieve_code() {
        let mut store = setup().await;
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();

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
        let store = setup().await;
        let email = Email::parse("nonexistent@example.com".to_string()).unwrap();
        let result = store.get_code(&email).await;

        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn should_remove_existing_code() {
        let mut store = setup().await;
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();

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
        let mut store = setup().await;
        let email = Email::parse("test@example.com".to_string()).unwrap();
        let initial_id = LoginAttemptId::default();
        let initial_code = TwoFACode::parse("123456".to_string()).unwrap();

        store.add_code(email.clone(), initial_id, initial_code)
            .await
            .expect("Failed to store initial code");

        let new_id = LoginAttemptId::default();
        let new_code = TwoFACode::parse("654321".to_string()).unwrap();

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