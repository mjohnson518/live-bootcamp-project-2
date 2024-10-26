use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json,
    extract::State,  // Add this
};
use serde::{Deserialize, Serialize};
use crate::{
    domain::error::AuthAPIError,
    utils::auth::validate_token,
    app_state::AppState,  // Add this
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

pub async fn verify_token(
    State(state): State<AppState>,
    Json(payload): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let banned_token_store = state.banned_token_store.read().await;
    validate_token(&payload.token, banned_token_store.deref())
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;
    
    Ok((
        StatusCode::OK,
        Json(VerifyTokenResponse {
            message: "Token is valid".to_string()
        })
    ))
}