use axum::{
    Json, async_trait, extract::{FromRef, FromRequestParts, State}, http::{StatusCode, request::Parts}, response::IntoResponse
};
use jsonwebtoken::{decode,DecodingKey,Validation,Algorithm};
use serde::{Deserialize,Serialize};
use common::{redis, uuid::Uuid};

use crate::{handlers_auth::{Claims, KEYS}, state::AppState};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
  pub user_id: Uuid,
  pub org_id: Uuid,
  pub role: String,
  
  #[serde(skip)] 
  pub token: String,
}


#[async_trait]
impl <S> FromRequestParts<S> for SessionData 
  where
    S: Send + Sync,
    AppState: FromRef<S>
{
  type Rejection = (StatusCode,String);
  
  async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
    let app_state = AppState::from_ref(state);

    let auth_header = parts.headers.get("Authorization")
    .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".into()))?
    .to_str()
    .map_err(
      |_| 
      (StatusCode::UNAUTHORIZED, "Invalid header format".into()))?;

    if !auth_header.starts_with("Bearer") {
      return Err((StatusCode::UNAUTHORIZED, "Invalid token format".into()));
    }
    
    let token = if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
        stripped.trim() 
    } else {
        return Err((StatusCode::UNAUTHORIZED, "Invalid token format".to_string()));
    };
    
    let redis_key = format!("session:{}", token);

    let mut conn = app_state.redis.get().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis connection error")))?;

    
    let (session_json, _): (Option<String>, ()) = redis::pipe()
            .get(&redis_key)
            .expire(&redis_key, 86400) 
            .query_async(&mut conn)
            .await
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis error: {}", error)))?;

    let session_str = session_json.ok_or((StatusCode::UNAUTHORIZED, format!("Session expired or invalid")))?;

    let mut session_data: SessionData = serde_json::from_str(&session_str).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, format!("Session corrupted")))?;

    session_data.token = token.to_string();

    Ok(session_data)
  }

}