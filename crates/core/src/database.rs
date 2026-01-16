use sqlx::postgres::{PgPool,PgPoolOptions};
use std::time::Duration;

pub async fn get_db_connection(database_url: &str) -> Result<PgPool, sqlx::Error> {
  let pool = PgPoolOptions::new()
  .max_connections(50)
  .min_connections(5)
  .acquire_timeout(Duration::from_secs(5))
  .idle_timeout(Duration::from_secs(600))
  .connect(database_url).await?;

  Ok(pool)
}