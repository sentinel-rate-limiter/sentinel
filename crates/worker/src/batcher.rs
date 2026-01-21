use std::collections::HashMap;
use chrono::{DateTime, Utc, Timelike};
use uuid::Uuid;
use core::models::UsageEvent;
use sqlx::{self, PgPool};

#[derive(Hash, Eq, PartialEq,Debug)]
pub struct MetricKey{
  time_bucket: DateTime<Utc>,
  org_id: Uuid,
  rule_id: Uuid,
  identity_id: Uuid,
  status: String
}
#[derive(Debug)]
pub struct MetricValue {
  pub count: i64,
  pub total_cost: i64
}

#[derive(Debug)]
pub struct Batcher {
  pub pool: PgPool,
  pub buffer: HashMap<MetricKey, MetricValue>,
  pub max_batch_size: usize
}

impl Batcher {
  pub fn new(pool: PgPool, max_batch_size: usize) -> Self{
    Self { pool, buffer: HashMap::new(), max_batch_size }
  }

  pub fn add(&mut self, event:UsageEvent) {
    let key = MetricKey {
      time_bucket: event.timestamp.with_second(0).unwrap().with_nanosecond(0).unwrap(),
      org_id: event.org_id,
      rule_id: event.rule_id,
      identity_id: event.identity_id,
      status: event.status
    };

    let entry = self.buffer.entry(key).or_insert(MetricValue { count: 0, total_cost: 0 });
    entry.count +=1;
    entry.total_cost += event.cost as i64;
  }

  pub fn should_flush(&self) -> bool {
    self.buffer.len() >= self.max_batch_size 
  }

  pub async fn flush(&mut self) -> Result<(), sqlx::Error> {
    if self.buffer.is_empty() {
      return  Ok(());
    }
    tracing::info!("Flushing {} metrics to DB..", self.buffer.len());

    let mut tx = self.pool.begin().await?;

    for (key,val) in self.buffer.drain() {
      sqlx::query!(
            r#"
            INSERT INTO usage_metrics (time_bucket, org_id, rule_id, identity_id, request_count, total_cost)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (time_bucket, org_id, rule_id, identity_id) 
            DO UPDATE SET 
                request_count = usage_metrics.request_count + EXCLUDED.request_count,
                total_cost = usage_metrics.total_cost + EXCLUDED.total_cost
            "#,
            key.time_bucket,
            key.org_id,
            key.rule_id,
            key.identity_id,
            val.count,
            val.total_cost
        )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        tracing::info!("Flush Complete.");
        Ok(())

  }
}