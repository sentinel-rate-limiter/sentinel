use axum::{
    Json, async_trait, extract::{FromRef, FromRequestParts, State}, http::{StatusCode, request::Parts}, response::IntoResponse
};
use jsonwebtoken::{decode,DecodingKey,Validation,Algorithm};
use serde::{Deserialize,Serialize};
use common::uuid::Uuid;

use crate::handlers_auth::{Claims, KEYS};

pub struct AuthenticatedUser {
  pub user_id: Uuid,
  pub org_id: Uuid
}


#[async_trait]
impl <S> FromRequestParts<S> for AuthenticatedUser 
  where
    S: Send + Sync
{
  type Rejection = (StatusCode,String);
  
  async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
    let auth_header = parts.headers.get("Authorization")
    .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".into()))?
    .to_str()
    .map_err(
      |_| 
      (StatusCode::UNAUTHORIZED, "Invalid header format".into()))?;

    if !auth_header.starts_with("Bearer") {
      return Err((StatusCode::UNAUTHORIZED, "Invalid token format".into()));
    }

    let token = &auth_header[7..];
    let token_data = decode::<Claims>(token, &KEYS.decoding, &Validation::new(Algorithm::HS256))
    .map_err(|error| (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", error)))?;

    Ok(AuthenticatedUser { user_id: token_data.claims.sub, org_id: token_data.claims.org_id })
  }

}