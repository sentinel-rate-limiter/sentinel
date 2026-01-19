use core::sqlx::PgPool;
use core::cache::RedisPool;
use crate::kafka::KafkaProducer;

#[derive(Clone)]
pub struct AppState {
  pub db: PgPool,
  pub redis: RedisPool,
  pub kafka: KafkaProducer
}

impl AppState {
  pub fn new(db:PgPool,redis:RedisPool, kafka: KafkaProducer) -> Self {
    Self { db, redis, kafka }
  }
}