use argon2::{password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher,PasswordVerifier,SaltString},Argon2};

pub fn hash_password(password: &str) -> Result<String,String> { 
  let salt = SaltString::generate(&mut OsRng);
  let argon2 = Argon2::default();

  let password_hash = argon2.hash_password(password.as_bytes(), salt).map_err(|error| e.to_string())?.to_string();

  Ok(password_hash)
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool,String> {
  let parsed_hash = PasswordHash::new(hash).map_err(|error| error.to_string())?;
  Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
}