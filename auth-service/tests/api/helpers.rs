use sqlx::{postgres::PgConnectOptions, Connection, PgConnection};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use reqwest::{Client, cookie::Jar};
use uuid::Uuid;
use serde::Serialize;
use wiremock::MockServer;
use secrecy::{ExposeSecret, Secret};
use auth_service::utils::constants::DATABASE_URL;
use auth_service::{
    Application, 
    app_state::{AppState},
    services::{
        hashmap_user_store::HashmapUserStore,
        hashset_banned_token_store::HashsetBannedTokenStore,
        hashmap_two_fa_code_store::HashmapTwoFACodeStore,
        postmark_email_client::PostmarkEmailClient,
    },
    domain::{email::Email, email_client::EmailClient},
    utils::constants::test,
};

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: Client,
    pub email_server: MockServer,
    pub email_client: Arc<dyn EmailClient + Send + Sync>,
    db_name: String,         
    clean_up_called: bool,
}

impl TestApp {
    pub async fn new() -> Self {
        let email_server = MockServer::start().await;
        
        let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
        let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
        let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
        let email_client = Arc::new(configure_email_client(email_server.uri()));
        let db_name = Uuid::new_v4().to_string();
        
        let app_state = AppState::new(
            user_store,
            banned_token_store,
            two_fa_code_store,
            email_client.clone(),
        );

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

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
            http_client,
            email_server,
            email_client,
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

pub fn get_random_email() -> Secret<String> {
    Secret::new(format!("{}@example.com", Uuid::new_v4()))
}

fn configure_email_client(base_url: String) -> PostmarkEmailClient {
    let sender_email = Email::parse(Secret::new(test::email_client::SENDER.to_owned()))
        .expect("Invalid sender email address.");
    let timeout = test::email_client::TIMEOUT;
    let http_client = Client::builder()
        .timeout(timeout)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(
        base_url,
        sender_email,
        Secret::new("dummy-token".to_string()),
        http_client,
    )
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called {
            panic!("TestApp was dropped without calling clean_up()!");
        }
    }
}

async fn delete_database(db_name: &str) {
    let connection_options = PgConnectOptions::from_str(DATABASE_URL.expose_secret())
        .expect("Failed to parse PostgreSQL connection string");
    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

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
        .expect("Failed to terminate database connections.");

    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}