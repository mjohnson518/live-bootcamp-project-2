use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use crate::{ 
    app_state::AppState, 
    domain::{
        error::AuthAPIError, 
        user::User, 
        email::Email, 
        password::Password   
    },
};

#[tracing::instrument(name = "Signup", skip(state), fields(email = %request.email))]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>, 
) -> Result<impl IntoResponse, AuthAPIError> {
    tracing::debug!("Parsing credentials");
    
    let email = Email::parse(request.email)
        .map_err(|_| {
            tracing::error!("Invalid email format");
            AuthAPIError::InvalidCredentials
        })?;
    
    let password = Password::parse(request.password)
        .map_err(|_| {
            tracing::error!("Invalid password format");
            AuthAPIError::InvalidCredentials
        })?;

    let user = User::new(email, password, request.requires_2fa);
    
    tracing::debug!("Acquiring write lock on user store");
    let mut user_store = state.user_store.write().await;

    tracing::debug!("Checking if user already exists");
    if user_store.get_user(&user.email).await.is_ok() {
        tracing::warn!("Attempted to create account with existing email");
        return Err(AuthAPIError::UserAlreadyExists);
    }

    tracing::debug!("Adding user to database");
    user_store.add_user(user).await
        .map_err(|e| {
            tracing::error!("Failed to add user: {:?}", e);
            AuthAPIError::UnexpectedError
        })?;

    tracing::info!("User created successfully");
    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}