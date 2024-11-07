use crate::helpers::{get_random_email, TestApp};
use serde_json::json;
use auth_service::ErrorResponse;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    // TODO: add more malformed input test cases
    let test_cases = [
        json!({
            "password": "password123",
            "requires2FA": true
        }),
        // Add more test cases here
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    // Arrange
    let app = TestApp::new().await;
    let body = json!({
        "email": get_random_email(),
        "password": "password123",
        "requires2FA": false
    });

    // Act
    let response = app.post_signup(&body).await;

    // Assert
    assert_eq!(response.status().as_u16(), 201);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    
    let test_cases = vec![
        (json!({"email": "", "password": "password123", "requires2FA": false}), "empty email"),
        (json!({"email": "notanemail", "password": "password123", "requires2FA": false}), "invalid email"),
        (json!({"email": "user@example.com", "password": "short", "requires2FA": false}), "short password"),
    ];

    for (invalid_body, error_case) in test_cases {
        let response = app.post_signup(&invalid_body).await;
        
        assert_eq!(
            response.status().as_u16(),
            400,
            "Did not return 400 for {}",
            error_case
        );

        let error_response: ErrorResponse = response.json().await.expect("Failed to parse error response");
        assert_eq!(error_response.error, "Invalid credentials");
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;
    let email = get_random_email();
    
    let body = json!({
        "email": email,
        "password": "password123",
        "requires2FA": false
    });

    // First signup should succeed
    let response = app.post_signup(&body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Second signup with same email should fail
    let response = app.post_signup(&body).await;
    assert_eq!(response.status().as_u16(), 409);

    let error_response: ErrorResponse = response.json().await.expect("Failed to parse error response");
    assert_eq!(error_response.error, "User already exists");
    app.clean_up().await;
}