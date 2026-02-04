use std::env;

use moka::future::Cache;

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use common::{cache::RedisPool, chrono::Local, deadpool_redis::redis::AsyncCommands, models::{PlanLimits}, uuid::Uuid};
use rand::{Rng, distributions::Alphanumeric};
use sqlx::types::Json;

use crate::handlers_api_keys::OrgContext;

pub type LocalOrgCache = Cache<String,Option<OrgContext>>;

pub enum KeyType { 
  Live,
  Test
}

impl KeyType {
  fn as_str(&self) -> &'static str {
    match self {
      Self::Live => "live", 
      Self::Test => "test"
    }
  }
}

pub fn generate_api_key(key_type: KeyType) -> String {
  const LEN: usize = 32;

  let rng = rand::thread_rng();

  let random_part : String = rng
  .sample_iter(&Alphanumeric)
  .take(LEN)
  .map(char::from)
  .collect();

  format!("sk_{}_{}", key_type.as_str(), random_part)
}



pub async fn get_org_ctx(org_cache: &LocalOrgCache, raw_api_key: &str, db: PgPool, redis: RedisPool) -> Result<Option<OrgContext>, String> {
  
  let key_hash = hash_api_key(raw_api_key);

  if let Some(cached_org) = org_cache.get(&key_hash).await {
      match cached_org {
        Some(ctx) => return Ok(Some(ctx)),
        None => return Ok(None)
      }
  }

  let redis_key = format!("org_ctx:{}", key_hash);

  let mut conn = redis.get().await.map_err(|error| format!("Error connecting to redis: {}", error))?;

  let redis_result: Option<String> = conn.get(&redis_key).await.map_err(|error| format!("Error obtaining redis key: {}", error))?;
  
  if let Some(ctx_string) = redis_result {
    if let Ok(ctx) = serde_json::from_str::<OrgContext>(&ctx_string) {
      org_cache.insert(key_hash, Some(ctx.clone())).await;
      return Ok(Some(ctx));
    }
  }

  let record = sqlx::query!(
        r#"
        SELECT o.id as org_id, p.limits as "limits!: Json<PlanLimits>", o.billing_cycle_anchor as billing_cycle_anchor
        FROM organizations o
        JOIN plans p ON o.plan_id = p.id
        WHERE o.api_key_hash = $1 AND o.is_active = true
        "#,
        key_hash 
    )
    .fetch_optional(&db)
    .await
    .map_err(|e| e.to_string())?;

  match record {
    Some(record) => {
      let ctx = OrgContext {
        org_id: record.org_id,
        limits: record.limits.0,
        billing_anchor: record.billing_cycle_anchor
      };

      if let Ok(json_val) = serde_json::to_string(&ctx) {
          let _ : () = conn.set_ex(&redis_key, json_val, 60*60*24).await.map_err(|error| format!("Error while inserting into redis: {}",error))?;
      }

      org_cache.insert(key_hash, Some(ctx.clone())).await;

      Ok(Some(ctx))
    },
    None => {
      org_cache.insert(key_hash, None).await;
      Ok(None)
    }
  }
}

pub fn hash_api_key(raw_api_key: &str) -> String {
  let mut hasher = Sha256::new();
  hasher.update(raw_api_key.as_bytes());
  hasher.update(env::var("API_KEY_SECRET").expect("Error retriving API KEY SECRET var").as_bytes());
  hex::encode(hasher.finalize())
}




pub async fn rotate_api_key(
  org_ctx: &LocalOrgCache, 
  org_id: Uuid,
  db: &PgPool, 
  redis: &RedisPool) -> Result<String, String> {
    

  let current_org = sqlx::query!(
        "SELECT api_key_hash FROM organizations WHERE id = $1",
        org_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?
    .ok_or("Organization not found".to_string())?;

  let old_hash_opt = current_org.api_key_hash;

  let new_raw_key = generate_api_key(KeyType::Live);
  let new_hash = hash_api_key(&new_raw_key); 

  let rows_affected = sqlx::query!(
        r#"
        UPDATE organizations 
        SET api_key_hash = $1, updated_at = NOW()
        WHERE id = $2 
        "#,
        &new_hash,
        &org_id,
    )
    .execute(db)
    .await
    .map_err(|e| e.to_string())?
    .rows_affected();

  if rows_affected == 0 {
    return Err("Organization not found or invalid old API Key".to_string());
  }

  if let Some(old_hash) = old_hash_opt {
    let redis_key = format!("org_ctx:{}", old_hash);
    match redis.get().await {
      Ok(mut conn) => {
        let result: Result<(), _> = conn.del(&redis_key).await;
        if let Err(error) = result {
          tracing::error!("Failed to delete key from Redis (Consistency Risk): {}", error);
        }
      }, Err(error) => {
        tracing::error!("Failed to connect to Redis during rotation: {}", error);
      }
    };
    org_ctx.invalidate(&old_hash).await;
    tracing::info!("Old API Key invalidated for Org {}", org_id);
  } else {
    tracing::info!("New API Key generated for Org {} (First time generation)", org_id);
  }
  Ok(new_raw_key)
}




