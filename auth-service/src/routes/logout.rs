use axum::{
    http::StatusCode, 
    response::IntoResponse,
    extract::State,  
};
use axum_extra::extract::{cookie, CookieJar};
use time::Duration;
use crate::{
    domain::error::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
    app_state::AppState,  
};
use std::ops::Deref;

#[tracing::instrument(name = "Logout", skip(state, jar))]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    tracing::debug!("Getting JWT cookie");
    let cookie = jar
        .get(JWT_COOKIE_NAME)
        .ok_or_else(|| {
            tracing::warn!("No JWT cookie found");
            AuthAPIError::MissingToken
        })?;
    
    let token = cookie.value();
    
    tracing::debug!("Validating token");
    let banned_token_store = state.banned_token_store.read().await;
    validate_token(token, banned_token_store.deref())
        .await
        .map_err(|e| {
            tracing::warn!("Token validation failed: {:?}", e);
            AuthAPIError::InvalidToken
        })?;
    drop(banned_token_store);

    tracing::debug!("Banning token");
    let banned_token_store = state.banned_token_store.write().await;
    banned_token_store
        .store_token(token.to_string())
        .await
        .map_err(|e| {
            tracing::error!("Failed to ban token: {:?}", e);
            AuthAPIError::UnexpectedError(e.into())
        })?;
        
    tracing::debug!("Removing JWT cookie");
    let removal_cookie = cookie::Cookie::build((JWT_COOKIE_NAME, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .http_only(true)
        .build();
    
    let jar = jar.remove(removal_cookie);
    
    tracing::info!("Logout successful");
    Ok((jar, StatusCode::OK))
}