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

#[tracing::instrument(name = "Verify 2FA", skip(state, jar))]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    tracing::debug!("Parsing email");
    let email = Email::parse(request.email)
        .map_err(|e| {
            tracing::warn!("Invalid email format: {:?}", e);
            AuthAPIError::InvalidCredentials
        })?;

    tracing::debug!("Parsing login attempt ID");
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|e| {
            tracing::warn!("Invalid login attempt ID: {:?}", e);
            AuthAPIError::InvalidCredentials
        })?;

    tracing::debug!("Parsing 2FA code");
    let two_fa_code = TwoFACode::parse(request.two_fa_code)
        .map_err(|e| {
            tracing::warn!("Invalid 2FA code: {:?}", e);
            AuthAPIError::InvalidCredentials
        })?;

    tracing::debug!("Getting 2FA code store");
    let mut two_fa_store = state.two_fa_code_store.write().await;

    tracing::debug!("Retrieving stored 2FA code");
    let (stored_id, stored_code) = two_fa_store.get_code(&email).await
        .map_err(|e| {
            tracing::warn!("Failed to get stored 2FA code: {:?}", e);
            AuthAPIError::IncorrectCredentials
        })?;

    tracing::debug!("Verifying 2FA code");
    if stored_id.as_ref() != login_attempt_id.as_ref() || stored_code.as_ref() != two_fa_code.as_ref() {
        tracing::warn!("2FA code mismatch");
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    tracing::debug!("Removing used 2FA code");
    two_fa_store.remove_code(&email).await
        .map_err(|e| {
            tracing::error!("Failed to remove 2FA code: {:?}", e);
            AuthAPIError::UnexpectedError(e.into())
        })?;

    tracing::debug!("Generating auth cookie");
    let cookie = generate_auth_cookie(&email).await
        .map_err(|e| {
            tracing::error!("Failed to generate auth cookie: {:?}", e);
            AuthAPIError::UnexpectedError(e.into())
        })?;

    tracing::info!("2FA verification successful");
    let jar = jar.add(cookie);
    
    (jar, Ok(StatusCode::OK.into_response()))
}
