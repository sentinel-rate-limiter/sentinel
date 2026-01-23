use axum::{
    Json, async_trait, extract::{FromRef, FromRequestParts, State}, http::{StatusCode, request::Parts}, response::IntoResponse
};
use crate::api_keys::{resolve_api_key, rotate_api_key};
use common::uuid::Uuid;
use serde_json::{self, json};

// TODO: RENAME MODUL CORE -> COMMON

use super::AppState;

pub struct AuthenticatedOrg {
  pub org_id: Uuid,
}

struct DeleteKeyRequest { 
  api_key: String,
  org_id: Uuid
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedOrg 
  where 
    S: Send + Sync, 
    AppState: axum::extract::FromRef<S>,
{
  type Rejection = (StatusCode, String);

  async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
      let app_state = AppState::from_ref(state);
      let api_key_header = parts.headers.get("X-Api-Key").ok_or((StatusCode::UNAUTHORIZED, "Missing X-Api-Key header".to_string()))?;
      let api_key = api_key_header
          .to_str()
          .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid Api Key format".to_string()))?
          .to_string();
      
      match resolve_api_key(app_state.api_key_cache, &api_key, app_state.db, app_state.redis).await {
        Ok(Some(org_id)) => {
          Ok(AuthenticatedOrg { org_id })
        },
        Ok(None) => {
          Err((StatusCode::UNAUTHORIZED, "Invalid API Key".to_string()))
        },
        Err(error) => {
          tracing::error!("Auth System Error: {}", error);

          Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Auth Service unavailable: {error}")))
        }
      }

  }
}


async fn rotate_api_key_handler(
  State(state): State<AppState>, 
  Json(payload): Json<DeleteKeyRequest>) -> impl IntoResponse
  {
    let rotation_result = rotate_api_key(
        &state.api_key_cache, 
        &payload.api_key, 
        payload.org_id, 
        &state.db, 
        &state.redis
    ).await;

    match rotation_result {
      Ok(new_raw_key) => {
         (StatusCode::OK, Json(json!({
                "status": "ok",
                "message": "API Key successfully rotated", 
                "new_api_key": new_raw_key
            })))
      },
      Err(error) => {
        if error == "Organization not found or invalid old API Key" {
          tracing::warn!("Failed rotation attempt for org {}: {}", payload.org_id, error);
          (StatusCode::UNAUTHORIZED, Json(json!({
            "status": "error",
            "message": "Invalid credentials provided"
          })))
        }else {
          tracing::error!("Error replacing rotating api keys: {error}");
          (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "status": "error",
            "message": "Internal server error"
          })))
        }
      }
    }
}
