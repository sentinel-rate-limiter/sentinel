use std::env;

use axum::{Json, extract::{Path, State, path}, http::StatusCode};
use common::{redis, uuid::Uuid};
use lettre::{Message, SmtpTransport, Transport, transport::smtp::authentication::Credentials};
use once_cell::sync::Lazy;
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};
use crate::{api_keys::{KeyType,generate_api_key, hash_api_key}, handlers_auth_token::SessionData, security::{hash_password, verify_password}, state::AppState};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx;
use serde_json::json;
use tracing;


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
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub role: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    token: String,
}

#[derive(Deserialize)]
pub struct ResendRequest {
    pub email: String,
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


#[tracing::instrument(
    name = "register_user", 
    skip(state, payload),  
    fields(               
        org_name = %payload.org_name,
        email = %payload.email,
        org_id = tracing::field::Empty, 
        user_id = tracing::field::Empty
    ),
    err(Debug) 
)]
pub async fn handle_register(State(state): State<AppState>, Json(payload): Json<RegisterRequest>) -> Result<Json<serde_json::Value>, (StatusCode,String)> {
  if payload.password != payload.confirm_password {
    tracing::warn!("Registration failed: Password mismatch");
    return Err((StatusCode::BAD_REQUEST, format!("Password and confirm password must be equal!")));
  } 
  let password_hash: String = hash_password(&payload.password).map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;


  let mut tx = state.db.begin().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
  let org_id = Uuid::new_v4();
  tracing::Span::current().record("org_id", &org_id.to_string());

 

  let default_plan = sqlx::query!(
    "SELECT id FROM plans WHERE is_default = TRUE LIMIT 1"
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to fetch default plan: {}", e)))?
    .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "System configuration error: No default plan exists".to_string()))?;

    let plan_id = default_plan.id;


  sqlx::query!(
    "INSERT INTO organizations (id, name, plan_id) VALUES ($1, $2, $3)",
        org_id, payload.org_name, plan_id
  ).execute(&mut *tx).await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

  let user_id = Uuid::new_v4();
  tracing::Span::current().record("user_id", &user_id.to_string());

    sqlx::query!(
        "INSERT INTO organization_user (id, org_id, email, password_hash, name, role, is_verified) VALUES ($1, $2, $3, $4, $5, 'admin', FALSE)",
        user_id, org_id, payload.email, password_hash, payload.name
    ).execute(&mut *tx).await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;


    sqlx::query!(
        "UPDATE organizations SET owner_id = $1 WHERE id = $2",
        user_id,
        org_id
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to set owner: {}", error)))?;

    tx.commit().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    tracing::info!("Organization and Admin User persisted in DB");

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
    
    tracing::info!("Registration process completed successfully");
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

    let session_token = Uuid::new_v4().to_string();
    let role = user.role.unwrap_or_else(|| "admin".to_string());

    let session_data = SessionData {
        user_id: user.id,
        org_id: user.org_id,
        role: role.clone(),
        token: session_token.clone()
    };

    let redis_key = format!("session:{}", session_token);
    let session_json = serde_json::to_string(&session_data)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization error: {}", error)))?;
    let ttl_seconds = 86400;

    let mut conn = state.redis.get().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis connection error")))?;

    let _ : () = redis::cmd("SETEX")
        .arg(&redis_key)
        .arg(ttl_seconds)
        .arg(session_json)
        .query_async(&mut conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis save error: {}", e)))?;

  Ok(Json(AuthResponse {
    token: session_token,
    user_id: user.id,
    org_id: user.org_id,
    role
  }))
}


pub async fn handle_verify_email(State(state): State<AppState>,Path(token_verification): Path<String>) 
-> Result<Json<AuthResponse>, (StatusCode, String)> {
    let mut conn = state.redis.get().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Redis error".to_string()))?;
    let redis_key = format!("verify_email:{}", token_verification);

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


    let session_token = Uuid::new_v4().to_string();
    let role = user.role.unwrap_or_else(|| "admin".to_string());
    let session_data = SessionData {
        user_id,
        org_id: user.org_id,
        role: role.clone(),
        token: session_token.clone()
    };

    let redis_key = format!("session:{}", session_token);
    let session_json = serde_json::to_string(&session_data)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization error: {}", error)))?;
    let ttl_seconds = 86400;

    let mut conn = state.redis.get().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis connection error")))?;

    let _ : () = redis::cmd("SETEX")
        .arg(&redis_key)
        .arg(ttl_seconds)
        .arg(session_json)
        .query_async(&mut conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis save error: {}", e)))?;

    Ok(Json(AuthResponse {
        token: session_token,
        org_id: user.org_id,
        user_id,
        role
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

async fn handle_logout(State(state): State<AppState>,  auth: SessionData) -> Result<StatusCode, (StatusCode,String)> {
    let mut conn = state.redis.get().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Redis error".to_string()))?;
    let redis_key = format!("session:{}", auth.token);

    let _: () = redis::cmd("DEL")
        .arg(&redis_key)
        .query_async(&mut conn)
        .await
        .unwrap_or(());

    Ok(StatusCode::OK)
}

// TODO: CONVERT INTO NON BLOCKING FUNCTION WITH TOKIO1 + lettre
async fn send_verification_email(email: &str, token: &str) -> Result<(), String> {
  
    let frontend_url = env::var("FRONTEND_URL").unwrap_or("http://localhost:3000".to_string());
    let verification_link = format!("{}/verify?token={}", frontend_url, token);

    let app_env = env::var("APP_ENV").unwrap_or("local".to_string());
    let smtp_host = env::var("SMTP_HOST").unwrap_or_default();

    if app_env == "local" || app_env == "dev" || smtp_host.is_empty() {
        tracing::info!("==================================================");
        tracing::info!("📧 [EMAIL MOCK - NO SE ENVIÓ NADA REAL]");
        tracing::info!("To: {}", email);
        tracing::info!("Link: {}", verification_link);
        tracing::info!("==================================================");
        return Ok(()); // <--- Retornamos éxito aquí y evitamos que lettre intente conectarse
    }


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