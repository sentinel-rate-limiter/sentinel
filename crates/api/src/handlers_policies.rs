use axum::{Json, extract::{Path, State}, http::{Response, StatusCode}};
use serde::{Deserialize, Serialize};
use common::{chrono, models::LimitAlgorithm, uuid::Uuid};
use crate::{state::AppState,handlers_auth_jwt::AuthenticatedUser};

#[derive(Deserialize)]
pub struct CreatePolicyRequest {
  pub name: String,
  pub description: String,
  pub is_default: bool
}

#[derive(Serialize)]
pub struct PolicyResponse {
  pub id: Uuid,
  pub name: String,
  pub description: String,
  pub is_default:bool,
  pub created_at: chrono::DateTime<chrono::Utc>
}

#[derive(Deserialize)]
pub struct UpdatePolicyRequest {
  name: Option<String>,
  description: Option<String>,
  is_default: Option<bool>
}

#[derive(Deserialize)]
pub struct CreateRuleRequest {
  pub resource_path: String,
  pub priority: i32,
  pub limit: i64,
  pub period: i32,
  pub cost: i32,
  pub algorithm: String
}

pub async fn create_policy(State(state): State<AppState>, auth: AuthenticatedUser, Json(payload): Json<CreatePolicyRequest>) -> Result<Json<PolicyResponse>, (StatusCode,String)> {
  let new_id = Uuid::new_v4();

  let mut tx = state.db.begin().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to begin transaction: {}", error)))?;
  if payload.is_default {
    sqlx::query!(
            r#"
            UPDATE policies 
            SET is_default = FALSE 
            WHERE org_id = $1 AND is_default = TRUE
            "#,
            auth.org_id
        )
        .execute(&mut *tx) // Usamos la transacción (*tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to demote old default: {}", e)))?;
  }

  let record = sqlx::query!(
        r#"
        INSERT INTO policies (id, org_id, name, description, is_default)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, description, is_default, created_at
        "#,
        new_id,
        auth.org_id,
        payload.name,
        payload.description,
        payload.is_default
    ).fetch_one(&mut *tx).await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error while inserting policy into db: {}", error)))?; 

    tx.commit().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to commit transaction: {}", error)))?;

    Ok(Json(PolicyResponse { id: record.id, name: record.name, description: record.description, is_default: record.is_default, created_at: record.created_at }))
}


pub async fn list_policies(
    State(state): State<AppState>,
    auth: AuthenticatedUser
) -> Result<Json<Vec<PolicyResponse>>, (StatusCode,String)> {
    let rows = sqlx::query!(
        r#"
        SELECT id, name, description, is_default, created_at
        FROM policies
        WHERE org_id = $1
        ORDER BY created_at DESC
        "#,
        auth.org_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

  let policies = rows.into_iter().map(|r| PolicyResponse {
    id: r.id,
    name: r.name,
    description: r.description,
    is_default: r.is_default,
    created_at: r.created_at
  }).collect();

  Ok(Json(policies))
}


pub async fn update_policy(State(state): State<AppState>, auth: AuthenticatedUser, Path(policy_id): Path<Uuid>,Json(payload): Json<UpdatePolicyRequest>) -> Result<Json<PolicyResponse>, (StatusCode, String)> {

    let mut tx = state.db.begin().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to begin transaction: {}", error)))?;


  if let Some(true) = payload.is_default {
    sqlx::query!(
            r#"
            UPDATE policies 
            SET is_default = FALSE 
            WHERE org_id = $1 AND is_default = TRUE
            "#,
            auth.org_id
        )
        .execute(&mut *tx) // Usamos la transacción (*tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to demote old default: {}", e)))?;
  }

  let record = sqlx::query!(
        r#"
        UPDATE policies 
        SET 
            name = COALESCE($1, name),
            description = COALESCE($2, description),
            is_default = COALESCE($3, is_default),
            updated_at = NOW() 
        WHERE id = $4 AND org_id = $5 
        RETURNING id, name, description, is_default, created_at
        "#,
        payload.name,        // $1
        payload.description, // $2
        payload.is_default,  // $3
        policy_id,           // $4
        auth.org_id          // $5
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error updating policy: {}", error)))?;

    tx.commit().await.map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to commit transaction: {}", error)))?;

    match record {
      Some(r) => Ok(Json(PolicyResponse {
            id: r.id,
            name: r.name,
            description: r.description,
            is_default: r.is_default,
            created_at: r.created_at,
        })),
        None => Err((StatusCode::NOT_FOUND, "Policy not found".to_string())),
    }

}

pub async fn delete_policy(State(state): State<AppState>, auth: AuthenticatedUser, Path(policy_id): Path<Uuid>) -> 
Result<(StatusCode,String),(StatusCode,String)>{
    let result = sqlx::query!(
        "DELETE FROM policies WHERE id = $1 AND org_id = $2",
        policy_id,
        auth.org_id 
    )
    .execute(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Error while deleting policy: {}", error)))?;

    if result.rows_affected() == 0 {
      return Err((StatusCode::NOT_FOUND, "Policy not found".to_string()));
    }

    Ok((StatusCode::NO_CONTENT, format!("Sucessfully deleted policy")))
}