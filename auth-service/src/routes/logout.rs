use axum::{http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie, CookieJar};
use std::time::Duration;
use crate::{
    domain::error::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(jar: CookieJar) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Get JWT cookie
    let cookie = jar
        .get(JWT_COOKIE_NAME)
        .ok_or(AuthAPIError::MissingToken)?;
    
    let token = cookie.value();
    
    // Validate the token
    validate_token(token)
        .await
        .map_err(|_| AuthAPIError::InvalidToken)?;
        
    // Remove the JWT cookie
    let removal_cookie = cookie::Cookie::build((JWT_COOKIE_NAME, ""))
        .path("/")
        .max_age(Duration::ZERO)  
        .http_only(true)
        .build();  // Changed from finish() to build()
    
    let jar = jar.remove(removal_cookie);
    
    Ok((jar, StatusCode::OK))
}