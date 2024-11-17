use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use color_eyre::eyre::Context;
use crate::{
    app_state::AppState,
    AuthAPIError,
    domain::{
        email::Email,
        password::Password,
        data_stores::{LoginAttemptId, TwoFACode},
    },
    utils::auth::generate_auth_cookie,
};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Clone, PartialEq, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

#[tracing::instrument(name = "Login handler", skip(state, jar))]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    let (jar, result) = process_login(state, jar, request).await;
    (jar, result)
}

#[tracing::instrument(name = "Process login", skip(state, jar))]
async fn process_login(
    state: AppState,
    jar: CookieJar,
    request: LoginRequest,
) -> (CookieJar, Result<(StatusCode, Json<LoginResponse>), AuthAPIError>) {
    tracing::debug!("Parsing credentials");
    let email = Email::parse(request.email)
        .map_err(|e| {
            tracing::warn!("Invalid email format: {:?}", e);
            AuthAPIError::InvalidCredentials
        })?;

    let password = Password::parse(request.password)
        .map_err(|e| {
            tracing::warn!("Invalid password format: {:?}", e);
            AuthAPIError::InvalidCredentials
        })?;

    tracing::debug!("Validating user credentials");
    let user_store = state.user_store.read().await;
    user_store.validate_user(&email, &password).await
        .map_err(|e| {
            tracing::warn!("Invalid credentials: {:?}", e);
            AuthAPIError::IncorrectCredentials
        })?;

    tracing::debug!("Getting user details");
    let user = user_store.get_user(&email).await
        .map_err(|e| {
            tracing::error!("Failed to get user: {:?}", e);
            AuthAPIError::UnexpectedError(e.into())
        })?;

    tracing::debug!("Checking 2FA requirement");
    match user.requires_2fa {
        true => handle_2fa(&email, &state, jar).await,
        false => handle_no_2fa(&email, jar).await,
    }
}

#[tracing::instrument(name = "Handle 2FA login", skip(state, jar))]
async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    tracing::debug!("Generating 2FA credentials");
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    tracing::debug!("Storing 2FA code");
    let mut two_fa_store = state.two_fa_code_store.write().await;
    two_fa_store
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to store 2FA code: {:?}", e);
            AuthAPIError::UnexpectedError(e.into())
        })?;

    tracing::debug!("Sending 2FA email");
    state.email_client
        .send_email(
            email,
            "Your 2FA Code",
            &format!("Your verification code is: {}", two_fa_code.clone()),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to send 2FA email: {:?}", e);
            AuthAPIError::UnexpectedError(e.into())
        })?;

    tracing::info!("2FA setup successful");
    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
        two_fa_code: two_fa_code.to_string(),
    }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

#[tracing::instrument(name = "Handle non-2FA login", skip(jar))]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    tracing::debug!("Generating auth cookie");
    let cookie = generate_auth_cookie(email)
        .await
        .map_err(|e| {
            tracing::error!("Failed to generate auth cookie: {:?}", e);
            AuthAPIError::UnexpectedError(e.into())
        })?;

    tracing::info!("Login successful");
    let jar = jar.add(cookie);
    let response = Json(LoginResponse::RegularAuth);
    
    (jar, Ok((StatusCode::OK, response)))
}