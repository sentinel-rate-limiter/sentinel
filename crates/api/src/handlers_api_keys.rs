use axum::{
    Json, async_trait, extract::{FromRef, FromRequestParts, State}, http::{StatusCode, request::Parts}, response::IntoResponse
};
use serde::{Deserialize, Serialize};
use crate::api_keys::{get_org_ctx, rotate_api_key};
use common::{ chrono::{DateTime, Utc}, models::PlanLimits, uuid::Uuid};
use serde_json::{self, json};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgContext {
    pub org_id: Uuid,
    pub limits: PlanLimits,
    pub billing_anchor: DateTime<Utc>
}

use super::AppState;

struct DeleteKeyRequest { 
  api_key: String,
  org_id: Uuid
}

#[async_trait]
impl<S> FromRequestParts<S> for OrgContext 
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
      
      match get_org_ctx(&app_state.org_cache, &api_key, app_state.db, app_state.redis).await {
        Ok(Some(ctx)) => {
          Ok(ctx)
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
        &state.org_cache, 
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
