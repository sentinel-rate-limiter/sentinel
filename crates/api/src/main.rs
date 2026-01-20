mod state;
mod kafka;

use axum::{Router, extract::State, http::StatusCode, routing::get, routing::post,Json};
use dotenvy::dotenv;
use moka::future::Cache;
use serde::Deserialize;
use tower::layer::util::Stack;
use tracing_subscriber::{EnvFilter, fmt::layer, layer::SubscriberExt, util::SubscriberInitExt};
use core::rules_manager::{get_policy_rules, match_rule};
use std::{env, time::Duration};
use std::net::SocketAddr;   
use core::{cache::get_redis_pool, chrono::Utc, database::get_db_connection, deadpool_redis::redis::cmd, limiter::check_rate_limit, models::UsageEvent, rules_manager::LocalCache, sqlx, uuid::Uuid};
use state::AppState;

use crate::kafka::send_event;



#[tokio::main]   
async fn main() -> Result<(), Box<dyn std::error::Error>>{

    dotenv().ok();
    
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).with(EnvFilter::from_default_env()).init();


    let database_url = env::var("database_url").expect("Could not find Database URL in the enviroment files...");
    let redis_host = env::var("redis_host").unwrap_or("localhost".to_string());
    let redis_port = env::var("redis_port").unwrap_or("6379".to_string());

    let redis_url = format!("redis://{redis_host}:{redis_port}");

    let kafka_url = env::var("KAFKA_URL").unwrap_or("localhost:9092".to_string());

    tracing::info!("Intializing API...");

    let redis_pool = get_redis_pool(&redis_url)?;
    let db_pool = get_db_connection(&database_url).await?;

    let kafka_producer = kafka::create_producer(&kafka_url);

    let local_cache: LocalCache = Cache::builder().time_to_live(Duration::from_secs(30)).max_capacity(10_000).build();


    let state = AppState::new(db_pool, redis_pool, kafka_producer, local_cache);

    let app = Router::new().route("/", get(health_check)).with_state(state.clone()).route("/check", post(handle_check_rate_limiter)).with_state(state.clone());

    let addr = SocketAddr::from(([0,0,0,0],3000));
    tracing::info!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    

    Ok(())
}

async fn health_check(State(state): State<AppState>) ->Result<String, StatusCode> {
    let row: (i32,) = sqlx::query_as("SELECT 1").fetch_one(&state.db).await.map_err(|e| {
        tracing::error!("Database connection failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!("Postgres connected succesfully! Ping to DB: {}", row.0);

    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::error!("Redis connection failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let pong : String = cmd("PING").query_async(&mut conn).await.map_err(|e|{
        tracing::error!("Redis Ping command failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    tracing::debug!("Redis connected. Response: {pong}");

    Ok("Service Running".to_string())
}

#[derive(Deserialize)]
struct CheckRequest {
    user_id: String,
    policy_id: Uuid,
    org_id: Uuid,
    request_path: String
}

// TODO: Complete Implementation
async fn handle_check_rate_limiter(State(state): State<AppState>, Json(payload): Json<CheckRequest>) -> Result<Json<serde_json::Value>, StatusCode>{
   

    let rules = get_policy_rules(&state.db, &state.redis, &state.local_cache, payload.policy_id).await.map_err(|error| {
        tracing::debug!("Error while fetching rules: {}",error);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let matched_rule = match_rule(&rules, &payload.request_path);


    let rule = match matched_rule {
        Some(r) => r,
        None => return Ok(Json(serde_json::json!({
            "status": "DENY",
            "message": "No matching rule for this path"
        })))
    };

    tracing::debug!("Rule matched: Rule {:?}", rule);

    let mut conn = state.redis.get().await.map_err(|e| {
            tracing::error!("Redis connection failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let key = format!("limiter:{}:{}:{}", payload.org_id, rule.id, payload.user_id);

    let result = check_rate_limit(&mut conn, &key, rule.limit_amount, rule.period_seconds, rule.cost_per_request).await.map_err(|e| {
        tracing::error!("Limit error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let producer = state.kafka.clone();
        tokio::spawn(async move {
            let event = UsageEvent {
                event_id: Uuid::new_v4(),
                org_id: None,
                rule_id:None,
                cost: rule.cost_per_request,
                user_id: payload.user_id.clone(),
                timestamp: Utc::now(),
                status: if result.allowed {"ALLOWED".to_string()} else {"DENIED".to_string()}
            };

            if let Ok(json_payload) = serde_json::to_string(&event) {
                send_event(&producer, "usage-logs", payload.user_id.clone(), json_payload).await;
            }
        });

    if result.allowed {
        Ok(Json(serde_json::json!({
            "status": "ALLOW",
            "remaining": result.remaining_tokens
        })))
    }else{
         Ok(Json(serde_json::json!({
            "status": "DENY",
            "remaining": result.remaining_tokens,
            "message" : "Rate limit exceded"
        })))
    } 
}