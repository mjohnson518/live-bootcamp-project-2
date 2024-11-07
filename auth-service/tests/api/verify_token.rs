use crate::helpers::{get_random_email, TestApp};
use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use serde_json::json;

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;
    
    // First sign up a user
    let email = get_random_email();
    let body = json!({
        "email": email,
        "password": "password123",
        "requires2FA": false
    });
    let signup_response = app.post_signup(&body).await;
    assert_eq!(201, signup_response.status().as_u16(), "Signup failed");
    
    // Then login to get a valid token
    let login_body = json!({
        "email": email,
        "password": "password123"
    });
    let login_response = app.post_login(&login_body).await;
    assert_eq!(200, login_response.status().as_u16(), "Login failed");
    
    // Extract the JWT token from the cookie
    let jwt_cookie = login_response.cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("JWT cookie not found");
    
    // Verify the token
    let response = app.post_verify_token(&json!({
        "token": jwt_cookie.value()
    })).await;
    
    assert_eq!(200, response.status().as_u16());
    
    let json_response: serde_json::Value = response.json().await.unwrap();
    assert_eq!(json_response["message"], "Token is valid");
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    let response = app.post_verify_token(&json!({
        "token": "invalid_token"
    })).await;
    
    assert_eq!(401, response.status().as_u16());
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let response = app.post_verify_token(&json!({
        "not_token": "wrong_field"
    })).await;
    
    assert_eq!(422, response.status().as_u16());
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;
    let email = get_random_email();
    
    // First sign up a user
    let signup_body = json!({
        "email": email,
        "password": "password123",
        "requires2FA": false
    });
    app.post_signup(&signup_body).await;
    
    // Then login to get a valid token
    let login_body = json!({
        "email": email,
        "password": "password123"
    });
    let login_response = app.post_login(&login_body).await;
    
    // Get the token
    let token = login_response.cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No JWT cookie found")
        .value()
        .to_string();
    
    // Add the token to the banned token store
    app.banned_token_store
        .write()
        .await
        .store_token(token.clone())
        .await
        .expect("Failed to store token");
    
    // Verify the token - should fail because it's banned
    let response = app.post_verify_token(&json!({
        "token": token
    })).await;
    
    assert_eq!(401, response.status().as_u16());
    
    let error_response: ErrorResponse = response.json().await.unwrap();
    assert_eq!("Invalid token", error_response.error);
    app.clean_up().await;
}