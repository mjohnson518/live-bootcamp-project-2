use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use crate::{
    app_state::AppState,
    AuthAPIError,
    domain::{
        email::Email,
        data_stores::{LoginAttemptId, TwoFACode},
    },
    utils::auth::generate_auth_cookie,
};

#[derive(Debug, Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Parse and validate the email
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    // Parse and validate the login attempt ID
    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
        Ok(id) => id,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    // Parse and validate the 2FA code
    let two_fa_code = match TwoFACode::parse(request.two_fa_code) {
        Ok(code) => code,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    // Get write access to the 2FA code store (we need write access because we'll remove the code after successful verification)
    let mut two_fa_store = state.two_fa_code_store.write().await;

    // Get the stored code
    let (stored_id, stored_code) = match two_fa_store.get_code(&email).await {
        Ok(code) => code,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    // Verify the login attempt ID and 2FA code match
    if stored_id.as_ref() != login_attempt_id.as_ref() || stored_code.as_ref() != two_fa_code.as_ref() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    // Remove the code from the store so it can't be used again
    if let Err(_) = two_fa_store.remove_code(&email).await {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // Generate auth token and create cookie
    let cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    // Add the cookie to the jar
    let jar = jar.add(cookie);
    
    (jar, Ok(StatusCode::OK.into_response()))
}