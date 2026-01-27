use std::env;

use axum::{Json, extract::State, http::StatusCode};
use common::{chrono::{Duration, Utc}, redis, uuid::Uuid};
use lettre::{Message, SmtpTransport, Transport, transport::smtp::authentication::Credentials};
use once_cell::sync::Lazy;
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};
use crate::{api_keys::{KeyType,generate_api_key, hash_api_key}, security::{hash_password, verify_password}, state::AppState};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
use sqlx;
use axum_macros::debug_handler;
use serde_json::json;


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
pub async fn handle_register(State(state): State<AppState>, Json(payload): Json<RegisterRequest>) -> Result<Json<serde_json::Value>, (StatusCode,String)> {
  

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
        "INSERT INTO organization_user (id, org_id, email, password_hash, name, role, is_verified) VALUES ($1, $2, $3, $4, $5, 'admin', FALSE)",
        user_id, org_id, payload.email, password_hash, payload.name
    ).execute(&mut *tx).await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    tx.commit().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let mut conn = state.redis.get().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error connecting to redis: {}", error)))?;

    let verification_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let redis_key = format!("verify_email:{}", verification_token);

    redis::cmd("SETEX")
        .arg(&redis_key)
        .arg(900) 
        .arg(user_id.to_string())
        .query_async::<_, ()>(&mut conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis error: {}", e)))?;

    tokio::spawn(async move {
      if let Err(e) = send_verification_email(&payload.email, &verification_token).await {
          tracing::error!("Background email sending failed: {}", e);
      }
    });
    
    Ok(Json(json!({
        "status": "pending_verification",
        "message": "User registered. Please check your email to verify account.",
        "org_id": org_id 
    })))}

#[axum_macros::debug_handler]
pub async fn handle_login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Result<Json<AuthResponse>, (StatusCode,String)> {
    let user = sqlx::query!(
        "SELECT id, org_id, password_hash, is_verified, role FROM organization_user WHERE email = $1",
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

  if !user.is_verified.unwrap_or(false) {
    return Err((StatusCode::FORBIDDEN, "Please verify your email address first.".to_string()));
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


#[derive(Deserialize)]
pub struct VerifyRequest {
    token: String,
}

#[derive(Deserialize)]
pub struct ResendRequest {
    pub email: String,
}

pub async fn handle_verify_email(State(state): State<AppState>,Json(payload): Json<VerifyRequest>) 
-> Result<Json<AuthResponse>, (StatusCode, String)> {
  let mut conn = state.redis.get().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Redis error".to_string()))?;
  let redis_key = format!("verify_email:{}", payload.token);

  let user_id_str: String = redis::cmd("GET")
        .arg(&redis_key)
        .query_async(&mut conn)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid or expired verification token".to_string()))?;

  let user_id = Uuid::parse_str(&user_id_str).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "ID error".to_string()))?;

  let user = sqlx::query!(
        "UPDATE organization_user SET is_verified = TRUE WHERE id = $1 RETURNING org_id, role",
        user_id
    ).fetch_one(&state.db).await.map_err(|_| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

  let _ : () = redis::cmd("DEL").arg(&redis_key).query_async(&mut conn).await.unwrap_or(());

  let token = generate_jwt(user_id, user.org_id, &user.role.unwrap_or("admin".to_string())).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error generating token")))?;

  Ok(Json(AuthResponse {
        token,
        org_id: user.org_id,
        user_id
    }))
}

pub async fn handle_resend_verification(
    State(state): State<AppState>,
    Json(payload): Json<ResendRequest>
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {

    let user = sqlx::query!(
        "SELECT id, is_verified FROM organization_user WHERE email = $1",
        payload.email
    ).fetch_optional(&state.db)
     .await
     .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let user = match user {
        Some(u) => u,
        None => return Err((StatusCode::NOT_FOUND, "User not found".to_string())),
    };

    if user.is_verified.unwrap_or(false) {
        return Err((StatusCode::BAD_REQUEST, "User is already verified. Please login.".to_string()));
    }

    let new_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();

    let redis_key = format!("verify_email:{}", new_token);
    let mut conn = state.redis.get().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Redis error".to_string()))?;

    let _: () = redis::cmd("SETEX")
        .arg(&redis_key)
        .arg(900)
        .arg(user.id.to_string())
        .query_async(&mut conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis error: {}", e)))?;

    tokio::spawn(async move {
    if let Err(e) = send_verification_email(&payload.email, &new_token).await {
        tracing::error!("Background email sending failed: {}", e);
    }
    });

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Verification email resent."
    })))
}

// TODO: CONVERT INTO NON BLOCKING FUNCTION WITH TOKIO1 + lettre
async fn send_verification_email(email: &str, token: &str) -> Result<(), String> {
  
    let frontend_url = env::var("FRONTEND_URL").unwrap_or("http://localhost:3000".to_string());
    let verification_link = format!("{}/verify?token={}", frontend_url, token);

    let recipient_email = if env::var("APP_ENV").unwrap_or_default() == "test" {
        env::var("TEST_EMAIL_RECEIVER").unwrap_or(email.to_string())
    } else {
        email.to_string()
    };


    let email = Message::builder()
        .from("SaaS Support <no-reply@tusaas.com>".parse().map_err(|error| format!("{}",error))?)
        .to(recipient_email.parse().map_err(|error| format!("{}",error))?)
        .subject("Verifica tu cuenta")
        .header(lettre::message::header::ContentType::TEXT_HTML)
        .body(format!(
            "<h1>Bienvenido</h1>
             <p>Haz click en el siguiente enlace para verificar tu cuenta:</p>
             <a href='{}'>Verificar Cuenta</a>
             <p>O copia este link: {}</p>", 
            verification_link, verification_link
        ))
        .map_err(|e| e.to_string())?;

    let smtp_host = env::var("SMTP_HOST").unwrap_or_default();

    if smtp_host.is_empty() {
        tracing::info!("Skipping email send (No SMTP_HOST). Link: {}", verification_link);
        return Ok(());
    }


    let smtp_user = env::var("SMTP_USER").expect("SMTP_USER missing");
    let smtp_pass = env::var("SMTP_PASS").expect("SMTP_PASS missing");

    let creds = Credentials::new(smtp_user, smtp_pass);


    let mailer = SmtpTransport::relay(&smtp_host)
        .map_err(|e| e.to_string())?
        .credentials(creds)
        .build();

  
    match mailer.send(&email) {
        Ok(_) => {
            tracing::info!("Email sent successfully to {}", recipient_email);
            Ok(())
        },
        Err(e) => {
            tracing::error!("Could not send email: {:?}", e);
            Err(e.to_string())
        }
    }
}