use std::env;

use moka::future::Cache;

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use common::{cache::RedisPool, deadpool_redis::redis::AsyncCommands, uuid::Uuid};
use rand::{Rng, distributions::Alphanumeric};


pub type LocalApiKeyCache = Cache<String,Option<Uuid>>;

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



pub fn hash_api_key(raw_api_key: &str) -> String {
  let mut hasher = Sha256::new();
  hasher.update(raw_api_key.as_bytes());
  hasher.update(env::var("API_KEY_SECRET").expect("Error retriving API KEY SECRET var").as_bytes());
  hex::encode(hasher.finalize())
}


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


// TODO: Instead of rotating with old api keys implement auth with password confirm and rotate key
pub async fn rotate_api_key(
  api_key_cache: &LocalApiKeyCache, 
  old_raw_api_key: &str, 
  org_id: Uuid,
  db: &PgPool, 
  redis: &RedisPool) -> Result<String, String> {
    

  let old_hash = hash_api_key(old_raw_api_key);

  let new_raw_key = generate_api_key(KeyType::Live);

  let new_hash = hash_api_key(&new_raw_key); 

  let rows_affected = sqlx::query!(
        r#"
        UPDATE organizations 
        SET api_key_hash = $1, updated_at = NOW()
        WHERE id = $2 AND api_key_hash = $3
        "#,
        &new_hash,
        &org_id,
        &old_hash 
    )
    .execute(db)
    .await
    .map_err(|e| e.to_string())?
    .rows_affected();

  if rows_affected == 0 {
    return Err("Organization not found or invalid old API Key".to_string());
  }

  let redis_key = format!("apikey:{}", old_hash);

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

  api_key_cache.invalidate(&old_hash).await;

  Ok(new_raw_key)
}




