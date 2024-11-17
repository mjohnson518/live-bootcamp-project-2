use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json,
    extract::State,
};
use serde::{Deserialize, Serialize};
use crate::{
    domain::error::AuthAPIError,
    utils::auth::validate_token,
    app_state::AppState,
};
use std::ops::Deref;

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}

#[derive(Serialize)]
pub struct VerifyTokenResponse {
    message: String,
}

#[tracing::instrument(name = "Verify token", skip(state))]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(payload): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    tracing::debug!("Getting banned token store");
    let banned_token_store = state.banned_token_store.read().await;

    tracing::debug!("Validating token");
    validate_token(&payload.token, banned_token_store.deref())
        .await
        .map_err(|e| {
            tracing::warn!("Token validation failed: {:?}", e);
            AuthAPIError::InvalidToken
        })?;
    
    tracing::info!("Token validated successfully");
    Ok((
        StatusCode::OK,
        Json(VerifyTokenResponse {
            message: "Token is valid".to_string()
        })
    ))
}