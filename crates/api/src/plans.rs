use axum::http::StatusCode;
use sqlx::{PgPool, types::Json};
use common::{uuid::Uuid, models::PlanLimits};


pub async fn get_orgs_limits(db: &PgPool, org_id: Uuid) -> Result<PlanLimits, (StatusCode,String)> {
  let record = sqlx::query!(
        r#"
        SELECT p.limits as "limits!: Json<PlanLimits>"
        FROM organizations o
        JOIN plans p ON o.plan_id = p.id
        WHERE o.id = $1
        "#,
        org_id
    )
    .fetch_optional(db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Db error while searching org limits: {}", error)))?;

    match record {
      Some(r) => Ok(r.limits.0),
      None => Err((
            StatusCode::FORBIDDEN, 
            "Organization has no active plan assigned.".to_string()
        )),
    }
}