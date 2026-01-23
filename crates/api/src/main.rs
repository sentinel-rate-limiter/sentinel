mod state;
mod kafka;
mod handlers_api_keys;
mod api_keys;
mod security;
mod handlers_auth;
mod handlers_auth_jwt;
mod handlers_policies;

use axum::{Router, extract::State, http::StatusCode, routing::get, routing::post,Json};
use dotenvy::dotenv;
use moka::future::Cache;
use serde::Deserialize;
use tracing_subscriber::{EnvFilter, fmt::layer, layer::SubscriberExt, util::SubscriberInitExt};
use common::identity_manager::LocalAnchorCache;
use common::models::LimitAlgorithm;
use common::quota::check_monthly_quota;
use common::rules_manager::{get_policy_rules, match_rule};
use std::{env, time::Duration};
use std::net::SocketAddr;   
use common::{cache::get_redis_pool, chrono::Utc, database::get_db_connection, deadpool_redis::redis::cmd, limiter::check_rate_limit, models::UsageEvent, rules_manager::LocalCache, sqlx, uuid::Uuid};
use state::AppState;

use crate::api_keys::LocalApiKeyCache;
use crate::handlers_api_keys::AuthenticatedOrg;
use crate::kafka::send_event;
use handlers_auth::{handle_login,handle_register};



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

    let local_anchor_cache: LocalAnchorCache = Cache::builder().time_to_live(Duration::from_secs(30)).max_capacity(10_000).build();

    let local_api_key_cache : LocalApiKeyCache = Cache::builder().time_to_live(Duration::from_secs(30)).max_capacity(10_000).build();

    let state = AppState::new(db_pool, redis_pool, kafka_producer, local_cache, local_anchor_cache, local_api_key_cache);

    let auth_routes = Router::new().route("/auth/register", post(handle_register)).route("/auth/login", post(handle_login));
    let core_routes = Router::new().route("/", get(health_check)).route("/check", post(handle_check_request));

    let app = Router::new().merge(auth_routes).merge(core_routes).with_state(state);

    let addr = SocketAddr::from(([0,0,0,0],3000));
    tracing::info!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    

    Ok(())
}

async fn health_check(State(state): State<AppState>) -> Result<String, StatusCode> {
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
async fn handle_check_request(auth: AuthenticatedOrg, State(state): State<AppState>, Json(payload): Json<CheckRequest>) -> Result<Json<serde_json::Value>, StatusCode>{
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

 

    let result = if rule.algorithm == LimitAlgorithm::TokenBucket{
        let key = format!("limiter:{}:{}:{}", auth.org_id, rule.id, &payload.user_id);
        check_rate_limit(&mut conn, &key, rule.limit_amount, rule.period_seconds, rule.cost_per_request).await.map_err(|e| {
        tracing::error!("Limit error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        check_monthly_quota(&mut conn, &state.db , &state.local_anchor_cache , payload.org_id,payload.policy_id,rule.id,rule.limit_amount, rule.cost_per_request, &payload.user_id).await.map_err(|e| {
        tracing::error!("Limit error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
        })?
    };
    


    let producer = state.kafka.clone();
        tokio::spawn(async move {
            let event = UsageEvent {
                event_id: Uuid::new_v4(),
                org_id: payload.org_id,
                rule_id: rule.id,
                policy_id: payload.policy_id,
                cost: rule.cost_per_request,
                identity_id: payload.user_id.clone(),
                timestamp: Utc::now(),
                status: if result.allowed {"ALLOWED".to_string()} else {"DENIED".to_string()}
            };

            if let Ok(json_payload) = serde_json::to_string(&event) {
                send_event(&producer, "usage-logs", payload.user_id, json_payload).await;
            }
        });

    if result.allowed {
        Ok(Json(serde_json::json!({
            "status": true,
            "limit": result.limit,
            "used": result.used,
            "remaining": result.remaining
        })))
    }else{
         Ok(Json(serde_json::json!({
            "status": false,
            "remaining": result.remaining,
            "message" : "Rate limit exceded"
        })))
    } 
}



