use crate::{cache::RedisPool, identity_manager::{LocalAnchorCache, get_billing_anchor}, models::AccessDecision, time_utils::get_current_cycle_start};
use redis::Script;
use sqlx::PgPool;
use tracing_subscriber::fmt::format;
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



// TODO: 
pub async fn check_organization_monthly_quota(
  redis: &RedisPool,
  db: &PgPool, 
  org_id: Uuid,
  quota_limit: i64,
  cost: i64
) -> Result<AccessDecision, String> {
  let now = Utc::now();
  let key = format!("quota:{}-{}-{}", org_id, now.year(), now.month());
  Err("a".to_string())
}


pub async fn check_monthly_quota(
  conn: &mut Connection,
  db: &PgPool,
  anchor_cache: &LocalAnchorCache,

  org_id: Uuid,
  policy_id: Uuid,
  rule_id: Uuid,
  limit: i64,
  cost: i32,
  user_id: Uuid
) -> Result<AccessDecision,String>
{


  let billing_anchor = get_billing_anchor(db, conn, anchor_cache, user_id, org_id).await?;


  let now = Utc::now();
  let cycle_start = get_current_cycle_start(billing_anchor, now);
  let date_part = cycle_start.format("%Y-%m-%d").to_string();

  let key = format!("quota:{}:{}:{}:{}:{}", org_id, user_id, policy_id, rule_id, date_part);

  let ttl = 60 * 60 * 24 * 31;

  let script = Script::new(FIXED_WINDOW_SCRIPT);

  let result : i64 = script.key(&key).arg(limit).arg(cost).arg(ttl).invoke_async(conn).await.map_err(|e| format!("Redis Error: {e:?}"))?;

  match result { 
    -2 => return Ok(AccessDecision { allowed: false, limit: limit, used: limit, remaining: 0 }),
    val if val >= 0 => return Ok(AccessDecision { allowed: true, limit: limit, used: val, remaining: limit - val }),
    _ => {}
  }

  let cycle_start = get_current_cycle_start(billing_anchor, now);

  let row = sqlx::query!(
        r#"
        SELECT COALESCE(SUM(total_cost), 0)::BIGINT as "total!"
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

    let db_usage = row.total;

    if db_usage >= limit || (db_usage + cost as i64) > limit {
        let _ : () = conn.set_ex(&key, db_usage, ttl).await.map_err(|error| format!("Error writing quota into redis: {}", error))?;
        return Ok(AccessDecision { allowed: false, limit: limit, used: limit, remaining: 0 });
    }

    let new_value = db_usage + cost as i64;
    let _ : () = conn.set_ex(&key, new_value, ttl ).await.map_err(|error| format!("Error writing quota into redis: {}", error))?;
    
    Ok(AccessDecision { allowed: true, limit: limit, used: new_value, remaining: limit - new_value })
  
}