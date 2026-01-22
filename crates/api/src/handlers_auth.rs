use axum::{Json, extract::State, http::StatusCode};
use common::{chrono::{Duration, Utc}, sqlx, uuid::Uuid};
use serde::{Deserialize, Serialize};
use crate::{self,api_keys::{generate_api_key, hash_api_key}, security::{hash_password, verify_password}, state::AppState};
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{Utc, Duration};
use uuid::Uuid;

#[derive(Deserealize)]
pub struct RegisterRequest {
  pub org_name: String,
  pub name: String,
  pub email: String,
  pub password: String,
  pub confirm_password: String
}

#[derive(Deserealize)]
pub struct LoginRequest {
  pub email: String,
  pub password: String,
}

#[derive(Deserealize)]
pub struct AuthResponse {
  pub token: String,
  pub org_id: Uuid,
  pub user_id: Uuid
}

#[derive(Deserealize,Serialize)]
pub struct Claims {
  pub sub: String,
  pub org_id: String,
  pub role: String,
  pub exp: usize
}


pub async fn register(State(state): State<AppState>, Json(payload): Json<RegisterRequest>) -> Result<Json<AuthResponse, (StatusCode,String)>> {
  
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
        "INSERT INTO organization_users (id, org_id, email, password_hash, full_name, role) VALUES ($1, $2, $3, $4, $5, 'admin')",
        user_id, org_id, payload.email, password_hash, payload.name
    ).execute(&mut *tx).await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    tx.commit().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let token = generate_jwt(user_id, org_id, "admin")?;

    Ok(Json(AuthResponse { token, org_id, user_id }))
}


pub async fn login( State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Result<AuthResponse, (StatusCode,String)> {
    let user = sqlx::query!(
        "SELECT id, org_id, password_hash, role FROM organization_users WHERE email = $1",
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

  let token = generate_jwt(user.id, user.org_id, user.role.unwrap_or("admin"))?;

  Ok(Json(AuthResponse {
    token,
    user_id: user.id,
    org_id: user.org_id
  }))
}


fn generate_jwt(user_id: Uuid, org_id: Uuid, role: &str) -> Result<String, (StatusCode,String)> {
  let expiration = Utc::now().checked_add_signed(Duration::days(7)).expect("Invalid timestamp").timestamp() as usize;

  let claims = Claims {
    sub: user_id.to_string(),
    org_id: org_id.to_string(),
    role: role.to_string(),
    exp: expiration
  };

  let secret = std::env::var("JWT_SECRET").expect("Could not find JWT_SECRET variable");
  
  encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}