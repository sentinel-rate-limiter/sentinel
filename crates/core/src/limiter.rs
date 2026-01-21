use deadpool_redis::redis::{cmd,Script};
use deadpool_redis::Connection; 
use std::time::{SystemTime,UNIX_EPOCH};

use crate::models::AccessDecision;


const TOKEN_BUCKET_SCRIPT: &str = r#"
local key = KEYS[1]
local limit = tonumber(ARGV[1])      -- Bucket Max Capacity (ex. 10 tokens)
local period = tonumber(ARGV[2])     -- Time window (ex. 60s)
local cost = tonumber(ARGV[3])       -- Cost of request (ex. 1 token)
local now_s = tonumber(ARGV[4])      -- Timestamp (now) (seconds)

-- 1. Get bucket state
local state = redis.call("HMGET", key, "tokens", "last_refill")
local current_tokens = tonumber(state[1])
local last_refill = tonumber(state[2])

-- 2.Init if not exists
if current_tokens == nil then
    current_tokens = limit
    last_refill = now_s
end

-- 3. Calculate Refill
-- Seconds passed since last time
local delta = math.max(0, now_s - last_refill)
-- Tokens generated between that time window (limit / period = tokens per second)
local refill_rate = limit / period
local tokens_to_add = delta * refill_rate

-- 4. Update bucket
current_tokens = math.min(limit, current_tokens + tokens_to_add)
last_refill = now_s -- Update timestamp

-- 5. Verify if has enough tokens
local allowed = 0
if current_tokens >= cost then
    current_tokens = current_tokens - cost
    allowed = 1
end

-- 6. Save state (TTL: period * 2 to remove old keys)
redis.call("HMSET", key, "tokens", current_tokens, "last_refill", last_refill)
redis.call("EXPIRE", key, period * 2)

-- 7. Return result
-- Return: [allowed (1/0), remainin_tokens]
return { allowed, current_tokens }
"#;


pub async fn check_rate_limit(
  conn: &mut Connection,
  key: &str,
  limit: i64,
  period_seconds: i32,
  cost: i32
) -> Result<AccessDecision,String>{
  // Get current time in seconds
  let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_secs_f64();


  // Prepare Script
  let script = Script::new(TOKEN_BUCKET_SCRIPT);


  let result: (i32, f64) = script.key(key).arg(limit).arg(period_seconds).arg(cost).arg(now).invoke_async(conn).await.map_err(|e| format!("Redis Error: {e:?}"))?;

  Ok(AccessDecision { allowed: result.0 == 1, remaining: result.1 as i64, limit:limit, used: limit - result.1 as i64 })
 
}