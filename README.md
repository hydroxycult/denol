<div align="center">
  
# Single-File Deno API
A complete authentication and content system in one file, demonstrating security and architectural patterns typically found in multi-file production services.
</div>


<br>

## Features

* JWT access tokens (HS512) with CSRF protection
* Refresh tokens with hashed server-side storage
* Session tracking with JTI blacklist and revocation
* Double-submit CSRF token validation
* Bcrypt password hashing with configurable rounds
* Zod-based request validation
* Deno KV datastore
* Rate limiting for authentication endpoints
* HTML sanitization for user content
* Post creation, retrieval, tagging, and likes
* User registration with email verification
* Password reset with secure tokens
* Account lockout after failed login attempts
* Fully self-contained, no external database required

## Purpose

This project demonstrates how much functionality can fit in a single file while maintaining clarity and modern security practices. Perfect for:

* Learning Deno, KV, JWT, and TypeScript
* Reference implementation of secure API techniques
* Quick prototypes and small personal projects
* Foundation for multi-file or database-backed expansion

**Note:** Designed for hobby code and experimentation. Not intended for production deployments without architectural changes.

## Getting Started

### Quick Start

```bash
JWT_SECRET=$(openssl rand -base64 32) deno run --allow-net --allow-env --allow-read --unstable-kv server.ts
```

Server starts on `http://localhost:8000`

### Environment Variables

```bash
# Required
JWT_SECRET=<your-secret-key>

# Optional
PORT=8000
ENV=development
BCRYPT_ROUNDS=12
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
TRUST_PROXY=false
```

### Development Mode

```bash
JWT_SECRET=$(openssl rand -base64 32) deno run --watch --allow-net --allow-env --allow-read --unstable-kv server.ts
```

## API Examples

### Authentication

**Register:**
```bash
curl -X POST http://localhost:8000/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "email": "test@example.com", "pwd": "Password123!"}'
```

**Login:**
```bash
curl -X POST http://localhost:8000/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "pwd": "Password123!"}'
```

Returns `accessToken` and `csrfToken` for authenticated requests.

**Get current user:**
```bash
curl http://localhost:8000/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Posts

**Create:**
```bash
curl -X POST http://localhost:8000/v1/posts \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "My First Post", "body": "Hello, world!", "tags": ["test"], "published": true}'
```

**List:**
```bash
curl http://localhost:8000/v1/posts?page=1&limit=10
```

**Like:**
```bash
curl -X POST http://localhost:8000/v1/posts/POST_ID/like \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

## Architecture

Single-file structure includes:

* **Config** - Environment variables and constants
* **Types & Interfaces** - TypeScript definitions
* **Error Classes** - Custom error handling
* **Event Bus** - Decoupled event-driven architecture
* **Services** - User, Post, and Auth layers
* **Middleware** - CORS, rate limiting, auth, CSRF, logging
* **Route Handlers** - All API endpoints
* **Routing** - Pattern-based URL routing
* **Startup Logic** - Server initialization

## Security & Limitations

### Included Security Features

* Password hashing (bcrypt)
* JWT signing and verification
* CSRF token validation
* Rate limiting
* Input sanitization
* Session management

### Production Considerations

* Single-file design limits team scalability
* Deno KV has limited query capabilities
* In-memory rate limiting doesn't work across instances
* No schema migrations
* Email uses console logging (no SMTP)

For production, consider PostgreSQL, Redis, comprehensive logging, distributed locks, and extensive test coverage.

## Best For

* Learning Deno and modern API patterns
* Quick prototypes and MVPs
* Personal projects
* Reference implementations
* Experimentation

**This is hobby code. Have fun, experiment, and learn, but understand the tradeoffs before production use.**
