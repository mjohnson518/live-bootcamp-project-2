use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use crate::{
    app_state::AppState,
    domain::{email::Email, password::Password, error::AuthAPIError, data_stores::UserStore},
};

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::parse(request.password)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;
    
    // Validate user credentials
    user_store.validate_user(&email, &password).await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    // If we reach here, login was successful
    Ok(StatusCode::OK)
}
