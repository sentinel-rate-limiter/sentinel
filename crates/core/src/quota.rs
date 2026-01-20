use crate::{cache::RedisPool, time_utils::get_current_cycle_start};
use redis::Script;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Datelike, Utc};
use deadpool_redis::{Connection, redis::AsyncCommands};


// crates/core/src/quota.rs

const FIXED_WINDOW_SCRIPT: &str = r#"
local key = KEYS[1]
local cost = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

-- 1. Get current usage
local current = redis.call("GET", key)

-- Case A: Redis does not have the key
-- Return -1 - Fetches data from postgres
if not current then
    return -1
end

current = tonumber(current)

-- Case B: Limit exceeded
if current >= limit then
    return -2
end

-- Case C: Limit exceeded
if (current + cost) > limit then
    return -2
end

-- Caso D: Increment usage
local new_val = redis.call("INCRBY", key, cost)
redis.call("EXPIRE", key, ttl)

return new_val
"#;

pub struct QuotaResult {
  pub allowed: bool,
  pub limit: i64,
  pub used: i64,
  pub remaining: i64
}


pub async fn check_organization_monthly_quota(
  redis: &RedisPool,
  db: &PgPool, 
  org_id: Uuid,
  quota_limit: i64,
  cost: i64
) -> Result<QuotaResult, String> {
  let now = Utc::now();
  let key = format!("quota:{}-{}-{}", org_id, now.year(), now.month());
  Err("a".to_string())
}


pub async fn check_monthly_quota(
  conn: &mut Connection,
  db: &PgPool,
  key: &str,
  limit: i64,
  cost: i64,
  billing_anchor: DateTime<Utc>
) -> Result<QuotaResult,String>
{
  let now = Utc::now();
  let ttl = 60 * 60 * 24 * 31;
  // key quota: {org-id}-{user-id}-{policy-id}-{rule-id}
  let script = Script::new(FIXED_WINDOW_SCRIPT);

  let result : i64 = script.key(key).arg(limit).arg(cost).arg(ttl).invoke_async(conn).await.map_err(|e| format!("Redis Error: {e:?}"))?;

  match result { 
    -2 => return Ok(QuotaResult { allowed: false, limit: limit, used: limit, remaining: 0 }),
    val if val >= 0 => return Ok(QuotaResult { allowed: true, limit: limit, used: val, remaining: limit - val }),
    _ => {}
  }

  let cycle_start = get_current_cycle_start(billing_anchor, now);

  let row = sqlx::query!(
        r#"
        SELECT SUM(total_cost) as "total!"
        FROM usage_metrics
        WHERE org_id = $1 
          AND identity_id = $2 
          AND rule_id = $3 
          AND time_bucket >= $4
        "#,
        org_id,
        user_id,
        rule_id,
        cycle_start
    ).fetch_one(db).await.map_err(|error| format!("Error fetching DB quota: {}", error))?;

    let db_usage = row.total.unwrap_or(0);

    if db_usage >= limit || (db_usage + cost) > limit {
        let _ : () = conn.set_ex(key, db_usage, ttl).await.map_err(|error| format!("Error writing quota into redis: {}", error))?;
        return Ok(QuotaResult { allowed: false, limit: limit, used: limit, remaining: 0 });
    }

    let new_value = db_usage + cost;
    let _ : () = conn.set_ex(key, new_value, ttl ).await.map_err(|error| format!("Error writing quota into redis: {}", error))?;
    
    Ok(QuotaResult { allowed: true, limit: limit, used: new_value, remaining: limit - new_value })
  
}