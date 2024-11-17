use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use color_eyre::eyre;
use secrecy::Secret;
use crate::{ 
    app_state::AppState, 
    domain::{
        error::AuthAPIError, 
        user::User, 
        email::Email, 
        password::Password,
        data_stores::UserStoreError,
    },
};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[tracing::instrument(name = "Signup", skip(state, request))]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>, 
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    
    let password = Password::parse(request.password)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user = User::new(email, password, request.requires_2fa);
    
    let mut user_store = state.user_store.write().await;

    if let Err(e) = user_store.add_user(user).await {
        return match e {
            UserStoreError::UserAlreadyExists => Err(AuthAPIError::UserAlreadyExists),
            UserStoreError::UnexpectedError(e) => Err(AuthAPIError::UnexpectedError(e)),
            _ => Err(AuthAPIError::UnexpectedError(eyre::eyre!("Unexpected error during signup")))
        };
    }

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