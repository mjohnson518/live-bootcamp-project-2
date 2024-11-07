use std::sync::Arc;
use tokio::sync::RwLock;
use sqlx::PgPool;
use auth_service::{
    Application, 
    app_state::AppState, 
    services::data_stores::{  // Updated import path
        postgres_user_store::PostgresUserStore,
        hashset_banned_token_store::HashsetBannedTokenStore,
        hashmap_two_fa_code_store::HashmapTwoFACodeStore,
    },
    services::mock_email_client::MockEmailClient,
    utils::constants::{DATABASE_URL, prod},
    get_postgres_pool,
};

#[tokio::main]
async fn main() {
    println!("Starting application...");
    
    // Configure PostgreSQL and get connection pool
    let pg_pool = configure_postgresql().await;
    
    // Initialize stores with PostgreSQL
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashmapTwoFACodeStore::default()));
    let email_client = Arc::new(MockEmailClient::default());
    
    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );
    
    let app = match Application::build(app_state, prod::APP_ADDRESS).await {
        Ok(app) => {
            println!("Application built successfully. Listening on {}", app.address);
            app
        },
        Err(e) => {
            eprintln!("Failed to build app: {}", e);
            return;
        }
    };

    println!("Running application...");
    if let Err(e) = app.run().await {
        eprintln!("Failed to run app: {}", e);
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