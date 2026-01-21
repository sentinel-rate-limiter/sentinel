use serde::{Deserialize,Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use chrono::{DateTime,Utc};
use sqlx::types::Json;
// Enums

#[derive(Debug,Clone,Serialize,Deserialize,sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name="limit_algorithm",rename_all="snake_case")]
pub enum LimitAlgorithm{
  FixedWindow,
  TokenBucket
}

#[derive(Debug,Clone,Serialize,Deserialize,FromRow)]
pub struct Organizations {
  pub id: Uuid,
  pub name: String,
  #[serde(skip_serializing)]
  pub api_key_hash: String,
  pub is_active: bool,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
  pub owner_id: Option<Uuid>
}


#[derive(Debug,Clone,Serialize,Deserialize,FromRow)]
pub struct OrganizationUser{
  pub id: Uuid,
  pub org_id: String,
  pub name: String,
  pub email: String,
  #[serde(skip_serializing)]
  pub password_hash: String,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Policy {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Rule {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub algorithm: LimitAlgorithm,
    pub resource_path: String,
    
    // Accept some generic json
    pub match_condition: Option<Json<serde_json::Value>>, 
    
    pub priority: i32,
    pub limit_amount: i64,
    pub period_seconds: i32,
    pub cost_per_request: i32,
    pub created_at: DateTime<Utc>,
}


#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Identity {
    pub id: Uuid,
    pub org_id: Uuid,
    pub external_id: String,
    pub policy_id: Option<Uuid>,
    pub meta: Option<Json<serde_json::Value>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UsageMetric {
    pub time_bucket: DateTime<Utc>,
    pub org_id: Uuid,
    pub rule_id: Option<Uuid>, // Puede ser NULL si la métrica es global
    pub request_count: i64,
    pub total_cost: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEvent{
  pub event_id: Uuid,
  pub org_id: Uuid,
  pub rule_id: Uuid,
  pub policy_id: Uuid,
  pub identity_id: Uuid,
  pub cost: i32,
  pub timestamp: DateTime<Utc>,
  pub status: String
}

#[derive(Debug)]
pub struct AccessDecision {
  pub allowed: bool,
  pub limit: i64,
  pub used: i64,
  pub remaining: i64
}