use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use crate::domain::error::AuthAPIError;
use crate::utils::auth::validate_token;

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}

pub async fn verify_token(
    Json(payload): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the token
    validate_token(&payload.token)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;
    
    Ok(StatusCode::OK)
}