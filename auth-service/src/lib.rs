pub mod routes;

use axum::{serve::Serve, Router};
use std::error::Error;
use tower_http::services::ServeDir;

pub struct Application {
    server: Serve<Router, Router>,
    pub address: String,
}

impl Application {
    pub fn new(server: Serve<Router, Router>, address: String) -> Self {
        Self { server, address }
    }

    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", axum::routing::post(routes::signup))
            .route("/login", axum::routing::post(routes::login))
            .route("/logout", axum::routing::post(routes::logout))
            .route("/verify_2fa", axum::routing::post(routes::verify_2fa))
            .route("/verify_token", axum::routing::post(routes::verify_token))
            .route("/test", axum::routing::get(|| async { "Test route" }));

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Self::new(server, address))
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
