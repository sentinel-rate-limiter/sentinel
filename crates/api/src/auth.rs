use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
};

// TODO: RENAME MODUL CORE -> COMMON

use crate::state::{ AppState};

pub struct AuthenticatedOrg {
  pub org_id: Uuid,
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
