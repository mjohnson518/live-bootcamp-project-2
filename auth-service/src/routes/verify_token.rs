use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use crate::domain::error::AuthAPIError;
use crate::utils::auth::validate_token;

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}

#[derive(Serialize)]
pub struct VerifyTokenResponse {
    message: String,
}

pub async fn verify_token(
    Json(payload): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    println!("Verify token endpoint called with token: {}", payload.token);  // Add this
    
    validate_token(&payload.token)
        .await
        .map_err(|e| {
            println!("Token validation failed: {:?}", e);  // Add this
            AuthAPIError::InvalidToken
        })?;
    
    println!("Token validated successfully");  // Add this
    Ok((
        StatusCode::OK,
        Json(VerifyTokenResponse {
            message: "Token is valid".to_string()
        })
    ))
}