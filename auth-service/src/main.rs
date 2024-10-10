use auth_service::Application;

#[tokio::main]
async fn main() {
    println!("Starting application...");
    let app = match Application::build("0.0.0.0:3000").await {
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
