use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use common::{chrono::{DateTime, Utc}, deadpool_redis, identity_manager::IdentityContext, uuid::Uuid};
use crate::{handlers_api_keys::OrgContext, state::AppState};


#[derive(Deserialize)]
pub struct CreateIdentityRequest {
  pub external_id: String,
  pub policy_id: Uuid,
  pub billing_anchor: Option<DateTime<Utc>>
}
#[derive(Serialize)]
pub struct IdentityResponse {
  pub external_id: String,
  pub status: String,
  pub billing_anchor: DateTime<Utc>
}

pub async fn create_or_update_identity(
  State(state): State<AppState>, 
  auth: OrgContext, Json(payload): Json<CreateIdentityRequest>) 
  -> Result<Json<IdentityResponse>, (StatusCode,String)> {
    let policy_check = sqlx::query!(
        "SELECT id FROM policies WHERE id = $1 AND org_id = $2",
        payload.policy_id,
        auth.org_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to search policy: {}", error)))?;

  if policy_check.is_none() {
    return Err((StatusCode::BAD_REQUEST, format!("Policy invalid or does not belong to Org")));
  }

  let anchor = payload.billing_anchor.unwrap_or_else(Utc::now);

  let record = sqlx::query!(
        r#"
        INSERT INTO identities (org_id, external_id, policy_id, billing_cycle_anchor)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (org_id, external_id) 
        DO UPDATE SET 
            policy_id = EXCLUDED.policy_id,
            billing_cycle_anchor = COALESCE($5, identities.billing_cycle_anchor),
            updated_at = NOW()
        RETURNING external_id, created_at, updated_at, billing_cycle_anchor
        "#,
        auth.org_id,
        payload.external_id,
        payload.policy_id,
        anchor,
        payload.billing_anchor 
    )
    .fetch_one(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update db: {}", error)))?;


    let ctx = IdentityContext {
      policy_id: payload.policy_id,
      billing_anchor: record.billing_cycle_anchor.unwrap_or(anchor)
    };

    state.local_identity_cache.insert(payload.external_id.clone(), ctx.clone()).await;

    if let Ok(json_val) = serde_json::to_string(&ctx) {
      let redis_key = format!("identity:{}:{}", auth.org_id, payload.external_id);
      let mut conn = state.redis.get().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error connecting to redis: {}", error)))?;
      let _ : () = deadpool_redis::redis::AsyncCommands::set_ex(&mut conn, redis_key, json_val, 60 * 60 * 24).await.unwrap_or_else(|e| tracing::error!("Failed to populate Redis cache: {}", e));;
    }

  let status = if record.created_at == record.updated_at {
    "created"
  } else {
    "updated"
  };

  Ok(Json(IdentityResponse {
    external_id: record.external_id,
    status: status.to_string(),
    billing_anchor: record.billing_cycle_anchor.unwrap()
  }))

}


