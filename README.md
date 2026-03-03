# Sentinel 🛡️
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

const sdk = new Sdk({ apiKey: "sk_live_...", baseUrl: "[https://api.yourdomain.com](https://api.yourdomain.com)" });

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


## Architecture Under the Hood
Sentinel uses a Cache-First, Write-Through architecture:

Compute Layer (Rust/Axum): Stateless microservices built for maximum concurrency.

Caching & Limiting Layer (Redis): Executes Lua Scripts for atomic evaluate-and-increment operations, eliminating race conditions entirely.

Persistence Layer (PostgreSQL): The source of truth for organizations, identities, and policies. If Redis goes down, Postgres gracefully takes over.

## Tech Stack
Backend: Rust, Axum, Tokio, SQLx, Tower-HTTP.

Data Stores: PostgreSQL, Redis.

Client SDK: TypeScript, Node fetch, tsup (ESM/CommonJS support).
