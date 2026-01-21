use core::identity_manager::LocalAnchorCache;
use core::sqlx::PgPool;
use core::cache::RedisPool;
use crate::kafka::KafkaProducer;
use core::rules_manager::LocalCache;


#[derive(Clone)]
pub struct AppState {
  pub db: PgPool,
  pub redis: RedisPool,
  pub kafka: KafkaProducer,
  pub local_cache: LocalCache,
  pub local_anchor_cache: LocalAnchorCache
}

impl AppState {
  pub fn new(db:PgPool,redis:RedisPool, kafka: KafkaProducer, local_cache: LocalCache, local_anchor_cache: LocalAnchorCache) -> Self {
    Self { db, redis, kafka, local_cache, local_anchor_cache }
  }
}