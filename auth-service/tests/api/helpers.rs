use sqlx::{postgres::PgConnectOptions, Connection, PgConnection};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use reqwest::{Client, cookie::Jar};
use uuid::Uuid;
use serde::Serialize;
use auth_service::utils::constants::DATABASE_URL;

use auth_service::{
    Application, 
    app_state::{
        AppState,
        BannedTokenStoreType,
        TwoFACodeStoreType,
    },
    services::{
        hashmap_user_store::HashmapUserStore,
        hashset_banned_token_store::HashsetBannedTokenStore,
        hashmap_two_fa_code_store::HashmapTwoFACodeStore,
        mock_email_client::MockEmailClient,
    },
    domain::email_client::EmailClient,
    utils::constants::test,
};

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub email_client: Arc<dyn EmailClient + Send + Sync>,  // Changed from EmailClientType
    pub http_client: Client,
    db_name: String,         
    clean_up_called: bool,
}

impl TestApp {
    pub async fn new() -> Self {
        let pg_pool = configure_postgresql().await;
        let db_name = Uuid::new_v4().to_string();
        let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
        let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
        let email_client = Arc::new(MockEmailClient::default());
        
        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client.clone(),
        );

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let cookie_jar = Arc::new(Jar::default());
        
        let http_client = Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .expect("Failed to create HTTP client");

        Self { 
            address,
            cookie_jar,
            banned_token_store,
            two_fa_code_store,
            email_client,
            http_client,
            db_name,              
            clean_up_called: false,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn signup(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn login(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn verify_2fa(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify_2fa", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/verify_2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn verify_token(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/verify_token", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: Serialize,
    {
        self.http_client
            .post(&format!("{}/verify_token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn clean_up(&mut self) {
        delete_database(&self.db_name).await;
        self.clean_up_called = true;
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

// Implement Drop to enforce cleanup
impl Drop for TestApp {
fn drop(&mut self) {
    if !self.clean_up_called {
        panic!("TestApp was dropped without calling clean_up()!");
    }
}
}

async fn delete_database(db_name: &str) {
let postgresql_conn_url: String = DATABASE_URL.to_owned();
let connection_options = PgConnectOptions::from_str(&postgresql_conn_url)
    .expect("Failed to parse PostgreSQL connection string");
let mut connection = PgConnection::connect_with(&connection_options)
    .await
    .expect("Failed to connect to Postgres");

// Kill any active connections to the database
connection
    .execute(
        format!(
            r#"
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = '{}'
            AND pid <> pg_backend_pid();
            "#,
            db_name
        )
        .as_str(),
    )
    .await
    .expect("Failed to drop the database.");

// Drop the database
connection
    .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
    .await
    .expect("Failed to drop the database.");
}