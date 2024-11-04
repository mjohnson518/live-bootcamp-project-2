pub mod routes;
pub mod domain;
pub mod services;
pub mod app_state;
pub mod utils;

// Re-export important types at the crate root
pub use routes::login::{LoginResponse, TwoFactorAuthResponse};
pub use domain::error::AuthAPIError;

use axum::{
    serve::Serve, 
    Router, 
    response::{IntoResponse, Response, Json}, 
    http::{StatusCode, Method, HeaderName}, 
    routing::post
};
use std::error::Error;
use tower_http::{cors::CorsLayer, services::ServeDir};
use app_state::AppState;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};

pub struct Application {
    server: Serve<Router, Router>,
    pub address: String,
    state: AppState,
}

impl Application {
    pub fn new(server: Serve<Router, Router>, address: String, state: AppState) -> Self {
        Self { server, address, state }
    }

    pub async fn build(state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        // Allow the app service(running on our local machine and in production) to call the auth service
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            // TODO: Replace [YOUR_DROPLET_IP] with your Droplet IP address
            "http://68.183.141.53:8000".parse()?,
        ];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("cookie"),
                HeaderName::from_static("authorization"),
            ])
            .expose_headers([
                HeaderName::from_static("set-cookie"),
                HeaderName::from_static("authorization"),
            ])
            .allow_origin(allowed_origins);

        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify_2fa", post(routes::verify_2fa))
            .route("/verify_token", post(routes::verify_token))
            .route("/test", axum::routing::get(|| async { "Test route" }))
            .with_state(state.clone())
            .layer(cors); // Add CORS config to our Axum router

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Self::new(server, address, state))
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        // Add error logging here
        println!("Auth service error: {:?}", self);  // You can add this line to see all errors
        
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => {
                println!("User already exists error");  // Specific error logging
                (StatusCode::CONFLICT, "User already exists")
            },
            AuthAPIError::InvalidCredentials => {
                println!("Invalid credentials error");
                (StatusCode::BAD_REQUEST, "Invalid credentials")
            },
            AuthAPIError::IncorrectCredentials => {
                println!("Incorrect credentials error");
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            },
            AuthAPIError::MissingToken => {
                println!("Missing token error");
                (StatusCode::BAD_REQUEST, "Missing token")
            },
            AuthAPIError::InvalidToken => {
                println!("Invalid token error");
                (StatusCode::UNAUTHORIZED, "Invalid token")
            },
            AuthAPIError::UnexpectedError => {
                println!("Unexpected server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            },
        };

        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });

        (status, body).into_response()
    }
}

pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    // Create a new PostgreSQL connection pool with max 5 connections
    PgPoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await
}