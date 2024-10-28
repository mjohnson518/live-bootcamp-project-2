use crate::helpers::{TestApp, get_random_email};
use auth_service::{
    domain::{
        email::Email,
    },
    routes::TwoFactorAuthResponse,  // Import from routes module
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use serde_json::json;

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
    
    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse error response");
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
    
    let error_response = login_response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse error response");
    assert_eq!(error_response.error, "Incorrect credentials");
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;
    let random_email = get_random_email();
    
    // First, create a user
    let signup_body = json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Then try to login
    let login_body = json!({
        "email": random_email,
        "password": "password123"
    });
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    // Check that we got a JWT cookie
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    // Create a new test app instance
    let app = TestApp::new().await;
    
    // Generate a random email for the test
    let email = get_random_email();
    
    // First, create a user with 2FA enabled
    let signup_response = app.post_signup(&json!({
        "email": email.clone(),
        "password": "validpassword123",
        "requires2FA": true  // Enable 2FA for this user
    })).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    // Now try to login with correct credentials
    let login_response = app.post_login(&json!({
        "email": email.clone(),
        "password": "validpassword123"
    })).await;

    // Assert we get a 206 status code
    assert_eq!(login_response.status().as_u16(), 206);

    // Parse and verify the response body
    let response_body = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");
    
    // Verify the message
    assert_eq!(response_body.message, "2FA required");
    
    // Verify that a login attempt ID was returned and not empty
    assert!(!response_body.login_attempt_id.is_empty());

    // Get access to the 2FA code store
    let two_fa_store = app.two_fa_code_store.read().await;

    // Verify that a code was stored for this email
    let email_obj = Email::parse(email).expect("Failed to parse email");
    let stored_code = two_fa_store.get_code(&email_obj).await;
    
    // Assert that we can retrieve the code and that the login attempt ID matches
    match stored_code {
        Ok((stored_login_attempt_id, _)) => {
            assert_eq!(
                stored_login_attempt_id.as_ref(),
                &response_body.login_attempt_id,
                "Stored login attempt ID doesn't match the one sent to the client"
            );
        },
        Err(e) => panic!("Failed to retrieve stored 2FA code: {:?}", e),
    }
}