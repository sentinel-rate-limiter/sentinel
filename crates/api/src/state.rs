use common::identity_manager::{LocalIdentityCache};
use common::sqlx::PgPool;
use common::cache::RedisPool;
use crate::api_keys::LocalOrgCache;
use crate::kafka::KafkaProducer;
use common::rules_manager::LocalCache;


#[derive(Clone)]
pub struct AppState {
  pub db: PgPool,
  pub redis: RedisPool,
  pub kafka: KafkaProducer,
  pub local_cache: LocalCache,
  pub local_identity_cache: LocalIdentityCache,
  pub org_cache: LocalOrgCache
}

impl AppState {
  pub fn new(db:PgPool,redis:RedisPool, kafka: KafkaProducer, local_cache: LocalCache, local_identity_cache: LocalIdentityCache, org_cache: LocalOrgCache) -> Self {
    Self { db, redis, kafka, local_cache, local_identity_cache, org_cache }
  }
}