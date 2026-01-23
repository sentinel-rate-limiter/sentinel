use axum::{Json, extract::State, http::StatusCode};
use common::{chrono::{Duration, Utc}, uuid::Uuid};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use crate::{api_keys::{KeyType,generate_api_key, hash_api_key}, security::{hash_password, verify_password}, state::AppState};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
use sqlx;
use axum_macros::debug_handler;



#[derive(Deserialize)]
pub struct RegisterRequest {
  pub org_name: String,
  pub name: String,
  pub email: String,
  pub password: String,
  pub confirm_password: String
}

#[derive(Deserialize)]
pub struct LoginRequest {
  pub email: String,
  pub password: String,
}

#[derive(Deserialize,Serialize)]
pub struct AuthResponse {
  pub token: String,
  pub org_id: Uuid,
  pub user_id: Uuid
}

#[derive(Debug,Deserialize,Serialize)]
pub struct Claims {
  pub sub: String,
  pub org_id: String,
  pub role: String,
  pub exp: usize,
  pub iat: usize
}

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}
pub static KEYS: Lazy<Keys> = Lazy::new(||{
let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
let secret_bytes = secret.as_bytes();
  Keys { 
    encoding: EncodingKey::from_secret(secret_bytes),
    decoding: DecodingKey::from_secret(secret_bytes)
  }
});

#[axum_macros::debug_handler]
pub async fn handle_register(State(state): State<AppState>, Json(payload): Json<RegisterRequest>) -> Result<Json<AuthResponse>, (StatusCode,String)> {
  
  if payload.password != payload.confirm_password {
    return Err((StatusCode::BAD_REQUEST, format!("Password and confirm password must be equal!")));
  } 
  let password_hash: String = hash_password(&payload.password).map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;


  let mut tx = state.db.begin().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
  let org_id = Uuid::new_v4();
  let raw_api_key = generate_api_key(KeyType::Live);
  let hash_api_key = hash_api_key(&raw_api_key);
  sqlx::query!(
    "INSERT INTO organizations (id, name, api_key_hash) VALUES ($1, $2, $3)",
        org_id, payload.org_name, hash_api_key
  ).execute(&mut *tx).await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

  let user_id = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO organization_user (id, org_id, email, password_hash, name, role) VALUES ($1, $2, $3, $4, $5, 'admin')",
        user_id, org_id, payload.email, password_hash, payload.name
    ).execute(&mut *tx).await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    tx.commit().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let token = generate_jwt(user_id, org_id, "admin")?;

    Ok(Json(AuthResponse { token, org_id, user_id }))
}

#[axum_macros::debug_handler]
pub async fn handle_login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Result<Json<AuthResponse>, (StatusCode,String)> {
    let user = sqlx::query!(
        "SELECT id, org_id, password_hash, role FROM organization_user WHERE email = $1",
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;

  let valid = verify_password(&user.password_hash, &payload.password).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Hash verify error".to_string()))?;;
  
  if !valid {
    return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
  }

  let token = generate_jwt(user.id, user.org_id, &user.role.unwrap_or("admin".to_string()))?;

  Ok(Json(AuthResponse {
    token,
    user_id: user.id,
    org_id: user.org_id
  }))
}


fn generate_jwt(user_id: Uuid, org_id: Uuid, role: &str) -> Result<String, (StatusCode,String)> {
  let now = Utc::now();
  let expiration = Utc::now().checked_add_signed(Duration::days(7)).expect("Invalid timestamp").timestamp() as usize;
  
  let claims = Claims {
    sub: user_id.to_string(),
    org_id: org_id.to_string(),
    role: role.to_string(),
    exp: expiration,
    iat: now.timestamp() as usize
  };

  
  encode(&Header::default(), &claims, &KEYS.encoding).map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error while encoding key: {}", error)))
}