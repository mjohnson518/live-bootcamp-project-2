use std::sync::Arc;
use tokio::sync::RwLock;
use auth_service::{Application, app_state::AppState, services::hashmap_user_store::HashmapUserStore, utils::constants::prod,};

#[tokio::main]
async fn main() {
    println!("Starting application...");
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default()));
    let app_state = AppState::new(user_store);
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
