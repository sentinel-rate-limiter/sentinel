use deadpool_redis::{Config,Runtime,Pool};

pub type RedisPool = Pool;

pub fn get_redis_pool(redis_url: &str)-> Result<RedisPool, String>{
  let cfg = Config::from_url(redis_url);
  let pool = cfg.create_pool(Some(Runtime::Tokio1)).map_err(|e| format!("Error creating Redis pool: {}", e))?;

  Ok(pool)
} 