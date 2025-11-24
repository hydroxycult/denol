# Single-File Deno API

This repository contains a single-file Deno API that demonstrates a complete authentication and content system in a compact and approachable format. While the entire server is implemented in one file, it includes many security and architectural patterns typically found in multi-file production services.

This project is intended as a clean reference, an educational resource, or a base for experimentation.

---

## Features

* JWT access tokens (HS512) with CSRF protection.
* Refresh tokens with hashed server-side storage.
* Session tracking with JTI blacklist and revocation.
* Double-submit CSRF token validation.
* Bcrypt password hashing with configurable rounds.
* Zod-based request validation for all inputs.
* Deno KV used as a lightweight datastore.
* Rate limiting for authentication endpoints.
* HTML sanitization for user-generated content. 
* Post creation, retrieval, tagging, and like system.
* User registration with email verification flow.
* Password reset with secure tokens.
* Account lockout after failed login attempts.
* Fully self-contained, no external database required.

---

## Purpose

The goal of this project is to show how much functionality can be implemented in a single file while maintaining clarity, structure, and modern security practices. Although the single-file layout and KV storage are not ideal for large-scale production systems, this project serves well as:

* A reference implementation of secure API techniques.
* A learning tool for Deno, KV, JWT, and TypeScript.
* A minimal but functional API for testing or small personal projects.
* A foundation to expand into a multi-file or database-backed architecture.

**Important**: This is designed for **short hobby code and experimentation**. It is **not intended for large-scale or production deployments** without significant architectural changes.

---

## Running Locally

### Quick Start

```bash
JWT_SECRET=$(openssl rand -base64 32) deno run --allow-net --allow-env --allow-read --unstable-kv server.ts
```

The server will start on `http://localhost:8000` by default.

### Environment Variables

Create a `.env` file or export these variables:

```bash
# Required
JWT_SECRET=<your-secret-key-here>

# Optional (with defaults)
PORT=8000
ENV=development
BCRYPT_ROUNDS=12
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
TRUST_PROXY=false
```

### Development with Auto-Reload

```bash
JWT_SECRET=$(openssl rand -base64 32) deno run --watch --allow-net --allow-env --allow-read --unstable-kv server.ts
```

---

## API Usage

### Authentication

**Register a new user:**
```bash
curl -X POST http://localhost:8000/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "pwd": "Password123!"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8000/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "pwd": "Password123!"
  }'
```

Save the `accessToken` and `csrfToken` from the response.

**Get current user:**
```bash
curl http://localhost:8000/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Posts

**Create a post:**
```bash
curl -X POST http://localhost:8000/v1/posts \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My First Post",
    "body": "Hello, world!",
    "tags": ["test", "demo"],
    "published": true
  }'
```

**Get all posts:**
```bash
curl http://localhost:8000/v1/posts?page=1&limit=10
```

**Like a post:**
```bash
curl -X POST http://localhost:8000/v1/posts/POST_ID/like \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

---

## Project Structure

This repo intentionally keeps all logic in a single file for simplicity. It includes:

* **Config**: Environment variables and constants
* **Types & Interfaces**: TypeScript definitions
* **Error Classes**: Custom error handling
* **Event Bus**: Decoupled event-driven architecture
* **Services**: User, Post, and Auth service layers
* **Middleware**: CORS, rate limiting, auth, CSRF, logging
* **Route Handlers**: All API endpoints
* **Routing**: Pattern-based URL routing
* **Startup Logic**: Server initialization and admin setup

---

## Notes

### Security

This project includes real security mechanisms:
* Password hashing with bcrypt
* JWT signing and verification
* CSRF token validation
* Rate limiting
* Input sanitization
* Session management

However, for production use, consider:
* Moving to a modular file structure
* Replacing KV with PostgreSQL or similar
* Adding comprehensive logging and monitoring
* Implementing distributed locks
* Using Redis for rate limiting
* Adding extensive test coverage

### Limitations

* **Single-file design**: Not scalable for large teams
* **Deno KV storage**: Limited query capabilities, not distributed
* **In-memory rate limiting**: Won't work across multiple instances
* **No migrations**: Schema changes require manual KV updates
* **Basic email**: Uses console logging instead of real SMTP

### Use Cases

This codebase is perfect for:
* Learning Deno and modern API patterns
* Quick prototypes and MVPs
* Personal projects and side hustles
* Code golf and experimentation
* Reference for security implementations

---

## License - MIT
**Note**: This is hobby code. Have fun, break things, learn from it, but don't run it in production without understanding the tradeoffs!
