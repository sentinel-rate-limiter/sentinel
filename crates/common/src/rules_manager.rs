use crate::models::{LimitAlgorithm,Rule};
use crate::cache::RedisPool;
use deadpool_redis::Connection;
use sqlx::PgPool;
use uuid::Uuid;
use deadpool_redis::redis::AsyncCommands;
use glob::Pattern;
use moka::future::Cache;
use sqlx::types::Json;

pub type LocalCache = Cache<Uuid,Vec<Rule>>;


pub async fn get_policy_rules(
  db: &PgPool,
  redis: &mut Connection,
  local_cache: &LocalCache,
  policy_id: Uuid
) -> Result<Vec<Rule>,String> {


  if let Some(rules) = local_cache.get(&policy_id).await {
    tracing::debug!("Local Cache Catch. Fetching policy {} from Rust", policy_id);
    return Ok(rules)
  }

  let rules = fetch_from_infra(db, redis, policy_id).await?;

  local_cache.insert(policy_id, rules.clone()).await;

  Ok(rules)
}


pub async fn fetch_from_infra(
  db: &PgPool,
  redis: &mut Connection,
  policy_id: Uuid
) -> Result<Vec<Rule>, String>{
  let redis_key = format!("policy_rules:{}", policy_id);


  let cached_json: Option<String> = redis.get(&redis_key).await.map_err(|error| error.to_string())?;

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
            resource_path, match_condition as "match_condition?: Json<serde_json::Value>", 
            priority, 
            limit_amount, 
            period_seconds, 
            cost_per_request, 
            created_at
        FROM rules
        WHERE policy_id = $1
        ORDER BY priority DESC
        "#,
        policy_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| e.to_string())?;

  let rules: Vec<Rule> = rows;

  if !rules.is_empty() {
    let json_val = serde_json::to_string(&rules).unwrap();
    let _: () = redis.set_ex(&redis_key, json_val, 600).await.map_err(|error| error.to_string())?;
  }

  Ok(rules)
}


pub fn match_rule(rules: &[Rule], request_path: &str) -> Option<Rule> {
  for rule in rules {
    if let Ok(pattern) = Pattern::new(&rule.resource_path){
      if pattern.matches(request_path) {
        return Some(rule.clone());
      }
    }
  };
  None
}