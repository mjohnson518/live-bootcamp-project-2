use axum::{
    http::StatusCode, 
    response::IntoResponse,
    extract::State,  // Added
};
use axum_extra::extract::{cookie, CookieJar};
use time::Duration;
use crate::{
    domain::error::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
    app_state::AppState,  // Added
};
use std::ops::Deref;

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Get JWT cookie
    let cookie = jar
        .get(JWT_COOKIE_NAME)
        .ok_or(AuthAPIError::MissingToken)?;
    
    let token = cookie.value();
    
    // Validate the token
    let banned_token_store = state.banned_token_store.read().await;
    validate_token(token, banned_token_store.deref())
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;
    drop(banned_token_store);

    // Add token to banned token store
    let mut banned_token_store = state.banned_token_store.write().await;
    banned_token_store
        .store_token(token.to_string())
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;
        
    // Remove the JWT cookie
    let removal_cookie = cookie::Cookie::build((JWT_COOKIE_NAME, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .http_only(true)
        .build();
    
    let jar = jar.remove(removal_cookie);
    
    Ok((jar, StatusCode::OK))
}