use std::env;

use moka::future::Cache;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::cache::RedisPool;

pub type LocalApiKeyCache = Cache<String,Option<Uuid>>;

pub async fn resolve_api_key(api_key_cache: LocalApiKeyCache, raw_api_key: &str, db: PgPool, redis: RedisPool) -> Result<Option<Uuid>, String> {
  let key_hash = hash_api_key(raw_api_key);

  if let Some(cached_org) = api_key_cache.get(&key_hash).await {
      return Ok(cached_org);
  }

  let redis_key = format!("apikey:{}", key_hash);

  let mut conn = redis.get().await.map_err(|error| format!("Error connecting to redis: {}", error))?;

  let redis_result: Option<String> = conn.get(&redis_key).await.map_err(|error| format!("Error obtaining redis key: {}", error))?;
  
  if let Some(org_id_str) = redis_result {
    let org_uuid = Uuid::parse_str(&org_id_str).map_err(|error| format!("Error parsing Org Id into Uuid: {}", error))?;
    api_key_cache.insert(key_hash, Some(org_uuid)).await;
    return Ok(Some(org_uuid));
  }

  let record = sqlx::query!(
        "SELECT id FROM organizations WHERE api_key_hash = $1 AND is_active = true",
        key_hash 
    )
    .fetch_optional(&db)
    .await
    .map_err(|e| e.to_string())?;

  match record {
    Some(row) => {
      let org_id = row.id;

      let _ : () = conn.set_ex(&redis_key, org_id.to_string(), 60*60*24).await.map_err(|error| format!("Error while inserting into redis: {}",error))?;

      api_key_cache.insert(key_hash, Some(org_id)).await;

      Ok(Some(org_id))
    },
    None => {
      api_key_cache.insert(key_hash, None).await;
      Ok(None)
    }
  }
}

fn hash_api_key(raw_api_key: &str) -> String {
  let mut hasher = Sha256::new();
  hasher.update(raw_api_key.as_bytes());
  hasher.update(env::var("API_KEY_SECRET").expect("Error retriving API KEY SECRET var").as_bytes());
  hex::encode(hasher.finalize())
}

