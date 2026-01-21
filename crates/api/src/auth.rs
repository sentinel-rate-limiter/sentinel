use axum::{async_trait,extract::FromRequestParts,http::{request::Parts,StatusCode}};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use once_cell::sync::Lazy;
use serde::{Deserialize,Serialize};
use core::uuid::Uuid;
use std::env;


static KEYS: Lazy<DecodingKey> = Lazy::new(|| {
  let secret = env::var("JWT_SECRET").expect("JWT Secret must be set.");
  DecodingKey::from_secret(secret.as_bytes())
});

pub struct Claims {
  pub org_id: Uuid,
  pub policy_id: Uuid,
  pub user_id: String,
  pub request_path: String
}