use std::sync::Arc;
use tokio::sync::RwLock;
use sqlx::PgPool;
use auth_service::{
    Application, 
    app_state::AppState, 
    services::data_stores::{  
        PostgresUserStore,
        RedisBannedTokenStore,
        RedisTwoFACodeStore,
    },
    services::mock_email_client::MockEmailClient,
    utils::{constants::{DATABASE_URL, REDIS_HOST_NAME, prod}, tracing::init_tracing},
    get_postgres_pool,
    get_redis_client,
};

#[tokio::main]
async fn main() {
    // Initialize tracing
    init_tracing();
    
    tracing::info!("Starting application...");
    
    // Configure PostgreSQL and get connection pool
    let pg_pool = configure_postgresql().await;
    
    // Configure Redis and get connection
    let redis_connection = Arc::new(RwLock::new(configure_redis()));
    
    // Initialize stores with PostgreSQL and Redis
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(
        redis_connection.clone(),
    )));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(redis_connection)));
    let email_client = Arc::new(MockEmailClient::default());
    
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

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}