use crate::models::{LimitAlgorithm,Rule};
use crate::cache::RedisPool;
use sqlx::PgPool;
use uuid::Uuid;
use deadpool_redis::redis::AsyncCommands;
use glob::Pattern;
use moka::future::Cache;

pub type LocalCache = Cache<Uuid,Vec<CachedRule>>;


#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
struct CachedRule {
    pub id: Uuid,
    pub path_pattern: String,
    pub limit: u32,
    pub period: u32,
    pub cost: u32,
    pub algorithm: LimitAlgorithm,
    pub priority: i32,
}

pub async fn get_policy_rules(
  db: &PgPool,
  redis: &RedisPool,
  local_cache: &LocalCache,
  policy_id: Uuid
) -> Result<Vec<CachedRule>,String> {


  if let Some(rules) = local_cache.get(&policy_id).await {
    tracing::debug!("Local Cache Catch. Fetching policy {} from Rust", policy_id);
    return Ok(rules)
  }

  

  Err("a".to_string())


}


pub async fn fetch_from_infra(
  db: &PgPool,
  redis: &RedisPool,
  policy_id: Uuid
) -> Result<Vec<CachedRule>, String>{
  let redis_key = format!("policy_rules:{}", policy_id);
  let mut conn = redis.get().await.map_err(|error| error.to_string())?;


  let cached_json: Option<String> = conn.get(&redis_key).await.map_err(|error| error.to_string())?;

  if let Some(json) = cached_json {
    if let Ok(rules) = serde_json::from_str(&json) {
      tracing::debug!("Cache Catch. Fetching policy {} from Redis", policy_id);
      return Ok(rules)
    }
  }

  tracing::debug!("Cache Miss (L1 & L2). Fetching policy {} from DB", policy_id);

  let rows = sqlx::query_as!(
        Rule,
        r#"
        SELECT 
            id, policy_id, algorithm as "algorithm!: LimitAlgorithm", 
            resource_path, match_condition, priority, 
            limit_amount, period_seconds, cost_per_request, created_at
        FROM rules
        WHERE policy_id = $1
        ORDER BY priority DESC
        "#,
        policy_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| e.to_string())?;

  Err("a".to_string())
}