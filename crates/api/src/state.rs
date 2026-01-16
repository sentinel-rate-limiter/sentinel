use sqlx::PgPool;
use core::cache::RedisPool;

#[derive(Clone)]
pub struct AppState {
  pub db: PgPool,
  pub redis: RedisPool
}

impl AppState {
  pub fn new(db:PgPool,redis:RedisPool) -> Self {
    Self { db, redis }
  }
}