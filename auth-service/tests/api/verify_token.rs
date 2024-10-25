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
        "requires2FA": false  // Changed from twoFaEnabled to requires2FA
    });
    
    // Debug: Print signup request body
    println!("Signup request body: {:?}", body);
    
    let signup_response = app.post_signup(&body).await;
    
    // Store status before consuming the response
    let status = signup_response.status();
    
    // Debug: Print signup response
    println!("Signup response status: {}", status);
    let error_body = signup_response.text().await.unwrap();
    println!("Signup response body: {}", error_body);
    
    assert_eq!(201, status.as_u16(), "Signup failed");
    
    // Then login to get a valid token
    let login_body = json!({
        "email": email,
        "password": "password123"
    });
    let login_response = app.post_login(&login_body).await;
    
    // Store login status before any potential debug printing
    let login_status = login_response.status();
    assert_eq!(200, login_status.as_u16(), "Login failed");
    
    // Debug: Print all cookies
    let cookies: Vec<_> = login_response.cookies().collect();
    println!("Found {} cookies", cookies.len());
    for cookie in &cookies {
        println!("Cookie: {} = {}", cookie.name(), cookie.value());
    }
    
    // Extract the JWT token from the cookie
    let jwt_cookie = cookies.iter()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("JWT cookie not found");
    let token = jwt_cookie.value().to_string();
    
    // Verify the token
    let response = app.post_verify_token(&json!({
        "token": token
    })).await;
    
    assert_eq!(200, response.status().as_u16());
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
}