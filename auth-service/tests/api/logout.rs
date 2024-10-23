use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use crate::helpers::{TestApp, get_random_email};
use reqwest::Url;
use serde_json::json;


#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;
    let response = app.logout().await;
    assert_eq!(response.status().as_u16(), 400);
    
    let error_response: ErrorResponse = response.json().await.expect("Failed to parse error response");
    assert_eq!(error_response.error, "Missing token");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    
    // Add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse(&app.address).expect("Failed to parse URL"),
    );

    let response = app.logout().await;
    assert_eq!(response.status().as_u16(), 401);
    
    let error_response: ErrorResponse = response.json().await.expect("Failed to parse error response");
    assert_eq!(error_response.error, "Invalid token");
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;
    let email = get_random_email();
    
    // First, create a user
    let signup_response = app.post_signup(&json!({
        "email": email,
        "password": "password123",
        "requires2FA": false
    })).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    // Log in to get JWT cookie
    let login_response = app.post_login(&json!({
        "email": email,
        "password": "password123"
    })).await;
    assert_eq!(login_response.status().as_u16(), 200);

    // Try to logout
    let logout_response = app.logout().await;
    assert_eq!(logout_response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;
    let email = get_random_email();
    
    // First, create a user
    let signup_response = app.post_signup(&json!({
        "email": email,
        "password": "password123",
        "requires2FA": false
    })).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    // Log in to get JWT cookie
    let login_response = app.post_login(&json!({
        "email": email,
        "password": "password123"
    })).await;
    assert_eq!(login_response.status().as_u16(), 200);

    // First logout should succeed
    let first_logout = app.logout().await;
    assert_eq!(first_logout.status().as_u16(), 200);

    // Second logout should fail
    let second_logout = app.logout().await;
    assert_eq!(second_logout.status().as_u16(), 400);
    
    let error_response: ErrorResponse = second_logout.json().await.expect("Failed to parse error response");
    assert_eq!(error_response.error, "Missing token");
}