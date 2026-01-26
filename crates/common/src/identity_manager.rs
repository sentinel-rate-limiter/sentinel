use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use chrono::{DateTime, Utc};
use moka::future::Cache;
use deadpool_redis::{Connection, redis::AsyncCommands};
use uuid::Uuid;

use crate::cache::RedisPool;

pub type LocalIdentityCache = Cache<String, IdentityContext>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityContext {
  pub policy_id: Uuid,
  pub billing_anchor: DateTime<Utc>
}

pub async fn get_itentity_ctx(
  db: &PgPool,
  redis: &mut Connection,
  local_cache: &LocalIdentityCache,
  user_external_id: &str,
  org_id: Uuid
) -> Result<IdentityContext, String>{
  
  if let Some(ctx) = local_cache.get(user_external_id).await {
    return Ok(ctx);
  }

  let redis_key = format!("identity:{}:{}", org_id, user_external_id);

  let cached_json: Option<String> = redis.get(&redis_key).await.map_err(|error| format!("Error while reading into redis: {}", error))?;

  if let Some(json_str) = cached_json {
    if let Ok(ctx) = serde_json::from_str::<IdentityContext>(&json_str) {
      local_cache.insert(user_external_id.to_string(), ctx.clone()).await;
      return Ok(ctx);
    }
  }

  let record = sqlx::query!(
        r#"
        SELECT policy_id, billing_cycle_anchor 
        FROM identities 
        WHERE org_id = $1 AND external_id = $2
        "#,
        org_id,
        user_external_id
    )
    .fetch_optional(db)
    .await
    .map_err(|error| format!("DB Error: {}", error))?;

  let row = record.ok_or_else(|| format!("Identity not found"))?;

 let ctx = IdentityContext {
        policy_id: row.policy_id,
        billing_anchor: row.billing_cycle_anchor.unwrap_or_else(Utc::now),
  };

  if let Ok(json_val) = serde_json::to_string(&ctx) {
        let _: () = redis.set_ex(&redis_key, json_val, 60 * 60 * 24).await.unwrap_or(());
  }

  local_cache.insert(user_external_id.to_string(), ctx.clone()).await;

  Ok(ctx)
}