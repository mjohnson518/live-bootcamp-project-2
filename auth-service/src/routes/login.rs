use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use crate::{
    app_state::AppState,
    domain::{email::Email, password::Password, error::AuthAPIError, data_stores::UserStore},
    utils::auth::generate_auth_cookie,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Parse and validate email and password
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::parse(request.password)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    // Validate credentials against user store
    let user_store = state.user_store.read().await;
    user_store.validate_user(&email, &password).await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    // Generate auth cookie
    let auth_cookie = generate_auth_cookie(&email)
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    // Add cookie to jar
    let jar = jar.add(auth_cookie);

    Ok((jar, StatusCode::OK))
}