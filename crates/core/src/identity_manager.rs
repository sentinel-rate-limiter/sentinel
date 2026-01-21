use crate::cache::RedisPool;
use sqlx::PgPool;
use chrono::{DateTime, Utc};
use moka::future::Cache;
use deadpool_redis::{Connection, redis::AsyncCommands};
use uuid::Uuid;

pub type LocalAnchorCache = Cache<String,DateTime<Utc>>;


pub async fn get_billing_anchor(
  db: &PgPool,
  redis: &mut Connection,
  local_cache: &LocalAnchorCache,
  user_external_id: &String,
  org_id: Uuid
) -> Result<DateTime<Utc>, String>{
  
  if let Some(anchor) = local_cache.get(&user_external_id.to_string()).await {
    return Ok(anchor);
  }

  let cache_key = format!("anchor:{}:{}", org_id, user_external_id);

  let cached_str: Option<String> = redis.get(&cache_key).await.map_err(|e| e.to_string())?;

  if let Some(s) = cached_str {
    if let Ok(date) = DateTime::parse_from_rfc3339(&s) {
      let utc_date = date.with_timezone(&Utc);
      local_cache.insert(user_external_id.to_string(), utc_date).await;
      return Ok(utc_date)
    }
  }

  let row = sqlx::query!(
    r#"SELECT billing_cycle_anchor FROM identities WHERE org_id = $1 AND external_id = $2"#,
        org_id,
        user_external_id.to_string()
    )
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?;
  
  let anchor = match row {
    Some(r) => r.billing_cycle_anchor.unwrap_or(Utc::now()),
    None => return Err("User identity not found".to_string())
  };

  let _: () = redis.set_ex(&cache_key, anchor.to_rfc3339(), 60 * 60 * 24)
        .await
        .map_err(|e| e.to_string())?;

  local_cache.insert(user_external_id.to_string(), anchor).await;

  Ok(anchor)
}