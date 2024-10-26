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

pub async fn logout(
    State(state): State<AppState>,  // Added
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Get JWT cookie
    let cookie = jar
        .get(JWT_COOKIE_NAME)
        .ok_or(AuthAPIError::MissingToken)?;
    
    let token = cookie.value();
    
    // Validate the token
    validate_token(token)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    // Add token to banned token store
    state
        .banned_token_store
        .write()
        .await
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