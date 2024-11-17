use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use color_eyre::eyre::{eyre, Context, Result};

use crate::domain::{email::Email, data_stores::BannedTokenStore};
use super::constants::{JWT_SECRET, JWT_COOKIE_NAME};

// This value determines how long the JWT auth token is valid for
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

#[tracing::instrument(name = "Generate auth cookie", skip(email))]
pub async fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email).await?;
    Ok(create_auth_cookie(token))
}

#[tracing::instrument(name = "Create auth cookie", skip(token))]
fn create_auth_cookie(token: String) -> Cookie<'static> {
    tracing::debug!("Creating auth cookie");
    Cookie::build((JWT_COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .domain("")
        .secure(false)
        .build()
}

#[tracing::instrument(name = "Generate auth token", skip(email))]
async fn generate_auth_token(email: &Email) -> Result<String> {
    tracing::debug!("Generating JWT token");
    
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .ok_or_else(|| eyre!("Failed to create duration from TOKEN_TTL_SECONDS"))?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or_else(|| eyre!("Failed to add duration to current time"))?
        .timestamp();

    let exp: usize = exp
        .try_into()
        .wrap_err("Failed to convert timestamp to usize")?;

    let sub = email.as_ref().to_owned();
    let claims = Claims { sub, exp };

    create_token(&claims).wrap_err("Failed to create JWT token")
}

#[tracing::instrument(name = "Create token", skip(claims))]
fn create_token(claims: &Claims) -> Result<String> {
    tracing::debug!("Encoding JWT token");
    encode(
        &jsonwebtoken::Header::default(),
        claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .wrap_err("Failed to encode JWT token")
}

#[tracing::instrument(name = "Validate token", skip(token, banned_token_store))]
pub async fn validate_token<T>(token: &str, banned_token_store: &T) -> Result<Claims>
where
    T: BannedTokenStore + ?Sized,
{
    tracing::debug!("Checking if token is banned");
    match banned_token_store.contains_token(token).await {
        Ok(true) => {
            tracing::warn!("Token is banned");
            return Err(eyre!("Token is banned"));
        }
        Ok(false) => {
            tracing::debug!("Token is not banned, proceeding with validation");
        }
        Err(e) => {
            tracing::error!("Failed to check if token is banned: {:?}", e);
            return Err(eyre!("Failed to check banned token status"));
        }
    }

    tracing::debug!("Decoding and validating JWT token");
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("Failed to decode or validate JWT token")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::data_stores::hashset_banned_token_store::HashsetBannedTokenStore;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let cookie = generate_auth_cookie(&email).await.unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let result = generate_auth_token(&email).await.unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).await.unwrap();
        let banned_token_store = HashsetBannedTokenStore::new();
        
        let result = validate_token(&token, &banned_token_store).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();
        let banned_token_store = HashsetBannedTokenStore::new();
        
        let result = validate_token(&token, &banned_token_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).await.unwrap();
        let mut banned_token_store = HashsetBannedTokenStore::new();
        
        banned_token_store.store_token(token.clone()).await.unwrap();
        
        let result = validate_token(&token, &banned_token_store).await;
        assert!(result.is_err());
    }
}