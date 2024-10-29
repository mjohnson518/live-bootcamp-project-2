use crate::helpers::{TestApp, get_random_email};
use auth_service::{
    domain::{
        email::Email,
        data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore},
    },
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use serde_json::json;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let response = app.post_verify_2fa(&json!({})).await;
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    
    let response = app.post_verify_2fa(&json!({
        "email": "notanemail",
        "loginAttemptId": "notauuid",
        "2FACode": "notasixdigitcode"
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
    
    // First create a user with 2FA enabled
    let signup_response = app.post_signup(&json!({
        "email": email.clone(),
        "password": "password123",
        "requires2FA": true
    })).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    // Try to verify with incorrect credentials
    let response = app.post_verify_2fa(&json!({
        "email": email,
        "loginAttemptId": "123e4567-e89b-12d3-a456-426614174000",
        "2FACode": "123456"
    })).await;

    assert_eq!(response.status().as_u16(), 401);
    
    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to parse error response");
    assert_eq!(error_response.error, "Incorrect credentials");
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
    let email = get_random_email();
    
    // First create a user with 2FA enabled
    let signup_response = app.post_signup(&json!({
        "email": email.clone(),
        "password": "password123",
        "requires2FA": true
    })).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    // Login to get the 2FA code
    let login_response = app.post_login(&json!({
        "email": email.clone(),
        "password": "password123"
    })).await;

    let login_body = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse login response");

    // Get the stored 2FA code
    let email_obj = Email::parse(email.clone()).expect("Failed to parse email");
    let two_fa_store = app.two_fa_code_store.read().await;
    let (_, stored_code) = two_fa_store
        .get_code(&email_obj)
        .await
        .expect("Failed to get stored 2FA code");

    // Verify the 2FA code
    let response = app.post_verify_2fa(&json!({
        "email": email,
        "loginAttemptId": login_body.login_attempt_id,
        "2FACode": stored_code.as_ref()
    })).await;

    assert_eq!(response.status().as_u16(), 200);

    // Check that we got a JWT cookie
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;
    let email = get_random_email();
    
    // First create a user with 2FA enabled
    let signup_response = app.post_signup(&json!({
        "email": email.clone(),
        "password": "password123",
        "requires2FA": true
    })).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    // Login to get the 2FA code
    let login_response = app.post_login(&json!({
        "email": email.clone(),
        "password": "password123"
    })).await;

    let login_body = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Failed to parse login response");

    // Get the stored 2FA code
    let email_obj = Email::parse(email.clone()).expect("Failed to parse email");
    let two_fa_store = app.two_fa_code_store.read().await;
    let (_, stored_code) = two_fa_store
        .get_code(&email_obj)
        .await
        .expect("Failed to get stored 2FA code");

    // First verification should succeed
    let verify_body = json!({
        "email": email,
        "loginAttemptId": login_body.login_attempt_id,
        "2FACode": stored_code.as_ref()
    });
    
    let response1 = app.post_verify_2fa(&verify_body).await;
    assert_eq!(response1.status().as_u16(), 200);

    // Second verification with same code should fail
    let response2 = app.post_verify_2fa(&verify_body).await;
    assert_eq!(response2.status().as_u16(), 401);
}