use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use crate::{app_state::AppState, domain::user::User};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>, 
) -> impl IntoResponse {
    let user = User::new(request.email, request.password, request.requires_2fa);
    let mut user_store = state.user_store.write().await;

    match user_store.add_user(user) {
        Ok(_) => {
            let response = Json(SignupResponse {
                message: "User created successfully".to_string(),
            });
            (StatusCode::CREATED, response)
        }
        Err(_) => {
            let response = Json(SignupResponse {
                message: "User creation failed".to_string(),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, response)
        }
    }
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}