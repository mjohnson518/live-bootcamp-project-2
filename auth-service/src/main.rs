use std::sync::Arc;
use tokio::sync::RwLock;
use sqlx::PgPool;
use reqwest::Client;
use secrecy::{ExposeSecret, Secret};
use auth_service::{
    Application, 
    app_state::AppState, 
    services::data_stores::{  
        PostgresUserStore,
        RedisBannedTokenStore,
        RedisTwoFACodeStore,
    },
    services::postmark_email_client::PostmarkEmailClient,
    domain::email::Email,
    utils::{constants::{DATABASE_URL, REDIS_HOST_NAME, POSTMARK_AUTH_TOKEN, prod}, tracing::init_tracing},
    get_postgres_pool,
    get_redis_client,
};

#[tokio::main]
async fn main() {
    init_tracing();
    
    tracing::info!("Starting application...");
    
    let pg_pool = configure_postgresql().await;
    let redis_connection = Arc::new(RwLock::new(configure_redis()));
    
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(
        redis_connection.clone(),
    )));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_connection)));
    let email_client = Arc::new(configure_email_client());
    
    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );
    
    let app = match Application::build(app_state, prod::APP_ADDRESS).await {
        Ok(app) => {
            tracing::info!("Application built successfully. Listening on {}", app.address);
            app
        },
        Err(e) => {
            tracing::error!("Failed to build app: {}", e);
            return;
        }
    };

    tracing::info!("Running application...");
    if let Err(e) = app.run().await {
        tracing::error!("Failed to run app: {}", e);
    }
}

fn configure_email_client() -> PostmarkEmailClient {
    let sender_email = Email::parse(Secret::new(prod::email_client::SENDER.to_owned()))
        .expect("Invalid sender email address.");
    let timeout = prod::email_client::TIMEOUT;
    let http_client = Client::builder()
        .timeout(timeout)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(
        prod::email_client::BASE_URL.to_owned(),
        sender_email,
        POSTMARK_AUTH_TOKEN.clone(),
        http_client,
    )
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.expose_secret().to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}