# Sentinel
**High-Performance Rate Limiting & API Gateway Engine**

Sentinel is a distributed API management system built in Rust. It provides sub-millisecond rate limiting, API key rotation, identity management, and secure session handling using Opaque Tokens. It comes with a fully-typed TypeScript SDK for seamless client integration.

## Objective
To provide a fast, reliable, and horizontally scalable layer to protect APIs from abuse and enforce billing quotas. Sentinel is built to handle granular limits—differentiating traffic by **Organization, Pricing Plan (Policies), and Request Routes**—without degrading the end-user experience or developer ergonomics.



## The Problem it Solves
1. **Granular Control Complexity:** Hardcoding limits for different routes and user tiers creates messy, unmaintainable code.
2. **Latency in Auth:** Traditional API gateways often require expensive database lookups on every request. 
3. **Race Conditions in Quotas:** Concurrent requests can bypass rate limits if the read-modify-write cycle isn't atomic.
4. **Inconsistent API Responses:** Dealing with changing JSON payloads when a limit is exceeded breaks client implementations.

## Developer Experience (DX): Simple & Predictable
Sentinel abstracts away the complexity of Redis Lua scripts, fallback databases, and caching. With the TypeScript SDK, managing identities and checking limits is effortless.

### 1. Attach a User to a Plan (Policy)
Create or update an identity, assigning them to a specific policy (which dictates their global and route-specific limits).

```typescript
import { Sdk } from "sentinel-sdk";

const sdk = new Sdk({ apiKey: "sk_live_...", baseUrl: "https://api.domain.com" });

const identity = await sdk.createOrModifyIdentity({
  externalId: "user-3",
  policyId: "0b3bb6f7-0d42-43b0-8f03-2f24e0fbe492",
});
```
### 2. Enforce Route-Specific Limits
Wrap your protected endpoints with a single call. Sentinel knows the user's organization, their assigned policy, and evaluates the limit for that exact path.

```typescript
const limit = await sdk.checkLimit({
  externalId: "user-3",
  requestPath: "/api/v1/test", // Sentinel evaluates limits specific to this route
});

if (!limit.status) {
  return Response.json({ error: limit.message }, { status: 429 });
}
```

3. Predictable Standardized Responses
No more guessing fields. Sentinel guarantees a standardized payload structure whether the request passes or fails, making your UI and error handling rock-solid.

Success (Status 200)

```
{
  "limit": 10,
  "message": "Ok",
  "remaining": 9,
  "status": true,
  "used": 1
}
```

Rate Limit Exceeded (Status 429)

```
{
  "limit": 10,
  "message": "Rate limit exceeded",
  "remaining": 0,
  "status": false,
  "used": 10
}
```

## Why not just use Nginx or Kong?

- Sentinel is designed for per-organization and per-route granular billing enforcement.
- Sub-millisecond Redis atomic evaluation.
- Fully-typed SDK (no manual header parsing).
- Built for product monetization use cases.


## Architecture Under the Hood
Sentinel uses a Cache-First, Write-Through architecture:

Compute Layer (Rust/Axum): Stateless microservices built for maximum concurrency.

Caching & Limiting Layer (Redis): Executes Lua Scripts for atomic evaluate-and-increment operations, eliminating race conditions entirely.

Persistence Layer (PostgreSQL): The source of truth for organizations, identities, and policies. If Redis goes down, Postgres gracefully takes over.

## Tech Stack
Backend: Rust, Axum, Tokio, SQLx, Tower-HTTP.

Data Stores: PostgreSQL, Redis.

Client SDK: TypeScript, Node fetch, tsup (ESM/CommonJS support).


# Sentinel Project API

## API Endpoint Documentation

The API exposes the following endpoints for managing identities, API keys, authentication, policies, and rules. All endpoints accept and return data in JSON format.

### Authentication

- **POST /auth/login**  
  Authenticates a user and returns a JWT token.  
  **Body:**  
  ```json
  { "username": "user", "password": "password" }
  ```
  **Example:**
  ```bash
  curl -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"user","password":"password"}'
  ```

- **POST /auth/refresh**  
  Refreshes the authentication token.  
  **Body:**  
  ```json
  { "refresh_token": "refresh_token_value" }
  ```
  **Example:**
  ```bash
  curl -X POST http://localhost:8000/auth/refresh \
    -H "Content-Type: application/json" \
    -d '{"refresh_token":"refresh_token_value"}'
  ```

### Identity Management

- **GET /identities**  
  Lists all registered identities.  
  **Example:**
  ```bash
  curl http://localhost:8000/identities
  ```

- **POST /identities**  
  Creates a new identity.  
  **Body:**  
  ```json
  { "name": "Name", "email": "email@example.com" }
  ```
  **Example:**
  ```bash
  curl -X POST http://localhost:8000/identities \
    -H "Content-Type: application/json" \
    -d '{"name":"Name","email":"email@example.com"}'
  ```

- **GET /identities/{id}**  
  Gets the details of a specific identity.  
  **Example:**
  ```bash
  curl http://localhost:8000/identities/123
  ```

- **PUT /identities/{id}**  
  Updates the data of an identity.  
  **Body:**  
  ```json
  { "name": "New Name", "email": "new@example.com" }
  ```
  **Example:**
  ```bash
  curl -X PUT http://localhost:8000/identities/123 \
    -H "Content-Type: application/json" \
    -d '{"name":"New Name","email":"new@example.com"}'
  ```

- **DELETE /identities/{id}**  
  Deletes an identity.  
  **Example:**
  ```bash
  curl -X DELETE http://localhost:8000/identities/123
  ```

### API Key Management

- **GET /api-keys**  
  Lists all API keys.  
  **Example:**
  ```bash
  curl http://localhost:8000/api-keys
  ```

- **POST /api-keys**  
  Creates a new API key.  
  **Body:**  
  ```json
  { "name": "Key Name" }
  ```
  **Example:**
  ```bash
  curl -X POST http://localhost:8000/api-keys \
    -H "Content-Type: application/json" \
    -d '{"name":"Key Name"}'
  ```

- **DELETE /api-keys/{id}**  
  Deletes an API key.  
  **Example:**
  ```bash
  curl -X DELETE http://localhost:8000/api-keys/456
  ```

### Policies and Rules

- **GET /policies**  
  Lists all policies.  
  **Example:**
  ```bash
  curl http://localhost:8000/policies
  ```

- **POST /policies**  
  Creates a new policy.  
  **Body:**  
  ```json
  { "name": "Example Policy", "description": "Policy description" }
  ```
  **Example:**
  ```bash
  curl -X POST http://localhost:8000/policies \
    -H "Content-Type: application/json" \
    -d '{"name":"Example Policy","description":"Policy description"}'
  ```

- **GET /rules**  
  Lists all rules.  
  **Example:**
  ```bash
  curl http://localhost:8000/rules
  ```

- **POST /rules**  
  Creates a new rule.  
  **Body:**  
  ```json
  { "name": "Example Rule", "condition": "Rule condition" }
  ```
  **Example:**
  ```bash
  curl -X POST http://localhost:8000/rules \
    -H "Content-Type: application/json" \
    -d '{"name":"Example Rule","condition":"Rule condition"}'
  ```

### Error Response Example

```json
{
  "error": "Error description",
  "code": 400
}
```

---

## 🚀 Quick Start

### Run with Docker

```bash
docker compose up --build

cargo run -p api
cargo run -p worker
```

![Rust](https://img.shields.io/badge/rust-1.75+-orange)


