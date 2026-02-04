use axum::{Json, extract::{Path, State}, http::StatusCode};
use common::{chrono, models::LimitAlgorithm};
use sqlx::types::Uuid;
use serde::{Serialize,Deserialize};

use crate::{handlers_auth_token::SessionData, handlers_policies::invalidate_policy_cache, plans::get_orgs_limits, state::AppState};


#[derive(Deserialize)]
pub struct CreateRuleRequest {
  pub policy_id: Uuid,
  pub resource_path: String,
  pub priority: i32,
  pub limit: i64,
  pub period: i32,
  pub cost: i32,
  pub algorithm: String
}


#[derive(Serialize)]
pub struct RuleResponse {
  pub id: Uuid,
  pub policy_id: Uuid,
  pub resource_path: String,
  pub priority: i32,
  pub limit: i64,
  pub period: i32,
  pub cost: i32,
  pub algorithm: LimitAlgorithm,
  pub created_at: chrono::DateTime<chrono::Utc>
}


#[derive(Deserialize)]
pub struct UpdateRuleRequest {
  pub resource_path: Option<String>,
  pub priority: Option<i32>,
  pub limit: Option<i64>,
  pub period: Option<i32>,
  pub cost: Option<i32>,
  pub algorithm: Option<String>
}

pub async fn create_rule(
  State(state): State<AppState>,
  auth: SessionData,
  Json(payload): Json<CreateRuleRequest>
) -> Result<Json<RuleResponse>, (StatusCode,String)> {


  let limits = get_orgs_limits(&state.db, auth.org_id).await?;

  let current_rules_count = sqlx::query!(
        r#"
        SELECT COUNT(r.id) as "count!"
        FROM rules r
        JOIN policies p ON r.policy_id = p.id
        WHERE p.org_id = $1
        "#,
        auth.org_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error while counting rules from db: {}", error)))?
    .count;

    if current_rules_count >= limits.max_rules as i64 {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Plan limit reached: You have {}/{} policies.", 
                current_rules_count, limits.max_rules
            )
        ));
    }


  let policy_exists = sqlx::query!(
        "SELECT id FROM policies WHERE id = $1 AND org_id = $2",
        payload.policy_id,
        auth.org_id
    ).fetch_optional(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to fetch rules in db: {}", error)))?;

    if policy_exists.is_none() {
      return Err((StatusCode::NOT_FOUND, format!("No policy was found within the organization")));
    }

    let algo = match payload.algorithm.as_str() {
      "token_bucket" => LimitAlgorithm::TokenBucket,
      "fixed_window" => LimitAlgorithm::FixedWindow,
      _ => return Err((StatusCode::BAD_REQUEST, format!("Invalid Algoritm")))
    };

    let rule_id = Uuid::new_v4();
    let record = sqlx::query!(
        r#"
        INSERT INTO rules 
        (id, policy_id, resource_path, priority, limit_amount, period_seconds, cost_per_request, algorithm)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING created_at, algorithm as "algorithm: LimitAlgorithm"
        "#,
        rule_id,
        payload.policy_id,
        payload.resource_path,
        payload.priority,
        payload.limit,
        payload.period,
        payload.cost,
        algo as LimitAlgorithm 
    )
    .fetch_one(&state.db)
    .await.map_err(|error |(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to insert rule into db: {}", error)))?;
  
    invalidate_policy_cache(&state, payload.policy_id).await;

    Ok(Json(RuleResponse {
      id: rule_id,
      policy_id: payload.policy_id,
      resource_path: payload.resource_path,
      limit: payload.limit,
      priority: payload.priority,
      period: payload.period,
      cost: payload.cost,
      algorithm: record.algorithm,
      created_at: record.created_at
    }))
}


pub async fn get_rule(
    State(state): State<AppState>,
    auth: SessionData,
    Path((policy_id, rule_id)): Path<(Uuid, Uuid)> // Asumimos ruta: /policies/:pid/rules/:rid
) -> Result<Json<RuleResponse>, (StatusCode, String)> {

    let record = sqlx::query!(
        r#"
        SELECT 
            r.id, 
            r.policy_id, 
            r.resource_path, 
            r.priority, 
            r.limit_amount, 
            r.period_seconds, 
            r.cost_per_request, 
            r.algorithm as "algorithm: LimitAlgorithm", 
            r.created_at
        FROM rules r
        INNER JOIN policies p ON r.policy_id = p.id
        WHERE r.id = $1 
          AND r.policy_id = $2 
          AND p.org_id = $3 
        "#,
        rule_id,
        policy_id,
        auth.org_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error fetching rule: {}", error)))?;

    match record {
        Some(r) => Ok(Json(RuleResponse {
            id: r.id,
            policy_id: r.policy_id,
            resource_path: r.resource_path,
            priority: r.priority,
            limit: r.limit_amount,
            period: r.period_seconds,
            cost: r.cost_per_request,
            algorithm: r.algorithm, 
            created_at: r.created_at,
        })),
        None => Err((StatusCode::NOT_FOUND, "Rule not found".to_string())),
    }
}


pub async fn list_rules(
    State(state): State<AppState>,
    auth: SessionData,
    Path(policy_id): Path<Uuid>
) -> Result<Json<Vec<RuleResponse>>, (StatusCode, String)> {

  let policy_exists = sqlx::query!(
        "SELECT id FROM policies WHERE id = $1 AND org_id = $2",
        policy_id,
        auth.org_id
    ).fetch_optional(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to fetch rules in db: {}", error)))?;

    if policy_exists.is_none() {
      return Err((StatusCode::NOT_FOUND, format!("No policy was found within the organization")));
    }


    let rows = sqlx::query!(
        r#"
        SELECT id, resource_path, priority, limit_amount, period_seconds, cost_per_request, algorithm as "algorithm: LimitAlgorithm", created_at
        FROM rules
        WHERE policy_id = $1
        ORDER BY priority ASC -- Generalmente queremos ver prioridades en orden
        "#,
        policy_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to fetch rules in db: {}", error)))?;

    let rules = rows.into_iter().map(|r| {
      RuleResponse {
        id: r.id,
        policy_id, 
        resource_path: r.resource_path,
        priority: r.priority,
        limit: r.limit_amount,
        period: r.period_seconds,
        cost: r.cost_per_request,
        algorithm: r.algorithm,
        created_at: r.created_at
      }
    }).collect();

    Ok(Json(rules))
}


pub async fn update_rule(
    State(state): State<AppState>,
    auth: SessionData,
    Path((policy_id, rule_id)): Path<(Uuid, Uuid)>, // Nested paths: /policies/:pid/rules/:rid
    Json(payload): Json<UpdateRuleRequest>
) -> Result<Json<RuleResponse>, (StatusCode, String)> {

  let algo = 
      match &payload.algorithm {
        Some(s) => match s.as_str() {
          "token_bucket" => Some(LimitAlgorithm::TokenBucket),
          "fixed_window" => Some(LimitAlgorithm::FixedWindow),
          _ => return Err((StatusCode::BAD_REQUEST, format!("Invalid Algoritm")))
        },
        None => None
    };

    let record = sqlx::query!(
        r#"
        UPDATE rules
        SET 
            resource_path = COALESCE($1, resource_path),
            priority      = COALESCE($2, priority),
            limit_amount  = COALESCE($3, limit_amount),
            period_seconds= COALESCE($4, period_seconds),
            cost_per_request = COALESCE($5, cost_per_request),
            algorithm     = COALESCE($6, algorithm)
        WHERE 
            id = $7 
            AND policy_id = $8
            AND policy_id IN (SELECT id FROM policies WHERE org_id = $9) -- 🔒 SEGURIDAD
        RETURNING 
            id, resource_path, priority, limit_amount, period_seconds, 
            cost_per_request, algorithm as "algorithm: LimitAlgorithm", created_at
        "#,
        payload.resource_path, // $1
        payload.priority,      // $2
        payload.limit,         // $3
        payload.period,        // $4
        payload.cost,          // $5
        algo as Option<LimitAlgorithm>, // $6
        rule_id,               // $7
        policy_id,             // $8
        auth.org_id            // $9
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Update failed in db: {}", error)))?; 

    
  match record {
    Some(r) => {
      
      invalidate_policy_cache(&state, policy_id).await;

      Ok(Json(RuleResponse {
          id: r.id,
          policy_id,
          resource_path: r.resource_path,
          priority: r.priority,
          limit: r.limit_amount,
          period: r.period_seconds,
          cost: r.cost_per_request,
          algorithm: r.algorithm,
          created_at: r.created_at,}))
    },
    None => Err((StatusCode::NOT_FOUND, format!("No rule found within the organization")))
  }
}



pub async fn delete_rule(
    State(state): State<AppState>,
    auth: SessionData,
    Path((policy_id, rule_id)): Path<(Uuid, Uuid)>
) -> Result<(StatusCode, String), (StatusCode, String)> {

    let result = sqlx::query!(
        r#"
        DELETE FROM rules 
        WHERE id = $1 
          AND policy_id = $2
          AND policy_id IN (SELECT id FROM policies WHERE org_id = $3) -- 🔒 SEGURIDAD
        "#,
        rule_id,
        policy_id,
        auth.org_id
    )
    .execute(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error deleting rule: {}", error)))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, format!("No rule found within the organization")))
    }

    invalidate_policy_cache(&state, policy_id).await;


    Ok((StatusCode::NO_CONTENT, format!("Successfully deleted rule")))
}