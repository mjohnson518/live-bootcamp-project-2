use crate::helpers::{TestApp, get_random_email};
use serde_json::json;
use auth_service::ErrorResponse;

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;
    let response = app.post_login(&json!({})).await;
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    
    let response = app.post_login(&json!({
        "email": "notanemail",
        "password": "password123"
    })).await;

    assert_eq!(response.status().as_u16(), 400);
    
    let error_response: ErrorResponse = response.json().await.expect("Failed to parse error response");
    assert_eq!(error_response.error, "Invalid credentials");
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    let email = get_random_email();
    
    // First, create a user
    let signup_response = app.post_signup(&json!({
        "email": email,
        "password": "validpassword123",
        "requires2FA": false
    })).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    // Now try to login with incorrect password
    let login_response = app.post_login(&json!({
        "email": email,
        "password": "wrongpassword"
    })).await;

    assert_eq!(login_response.status().as_u16(), 401);
    
    let error_response: ErrorResponse = login_response.json().await.expect("Failed to parse error response");
    assert_eq!(error_response.error, "Incorrect credentials");
}