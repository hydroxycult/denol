// auth + posts api
// stack: jwt/kv/bcrypt/csrf


import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { create, verify as verifyJwt } from "https://deno.land/x/djwt@v3.0.1/mod.ts";
import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";
import { DOMParser } from "https://deno.land/x/deno_dom@v0.1.45/deno-dom-wasm.ts";

// config

const env = Deno.env.get("ENV") || "development";
const jwt_secret = Deno.env.get("JWT_SECRET");
const port = parseInt(Deno.env.get("PORT") || "8000");
const allowed_origins = (Deno.env.get("ALLOWED_ORIGINS") || "http://localhost:3000")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const rate_window = 60; // secs
const rate_max = 100;
const login_rate_max = 5; // per IP and email
const token_exp = 15 * 60; // 15min
const refresh_exp = 7 * 24 * 60 * 60; // 7d
const bcrypt_rounds = parseInt(Deno.env.get("BCRYPT_ROUNDS") || "12", 10); // bcrypt rounds
const max_body = 10 * 1024 * 1024;
const max_fails = 5; // lockout after 5 fails
const lockout_time = 15 * 60 * 1000; // 15min
const max_user_posts = 1000;
const max_tag_posts = 10000;
const bind_ip = Deno.env.get("ENFORCE_IP_BINDING") === "true";
const trust_proxy = Deno.env.get("TRUST_PROXY") === "true";
const max_blacklist = 10000;
const max_sessions = 10;

// check jwt secret is strong
const check_secret = (secret: string): void => {
  if (!secret) {
    throw new Error("CRITICAL: jwt_secret environment variable is required");
  }
  if (env === "production") {
    if (secret === "change-this-secret-in-production") {
      throw new Error("CRITICAL: Default JWT secret detected in production. Set jwt_secret environment variable.");
    }
    if (secret.length < 32) {
      throw new Error("CRITICAL: JWT secret must be at least 32 characters in production");
    }
  }
};

// cache hmac key
let jwt_key: CryptoKey;
const initJwtKey = async () => {
  jwt_key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(jwt_secret!),
    { name: "HMAC", hash: "SHA-512" }, // don't mess with this, algorithms must match
    false,
    ["sign", "verify"]
  );
};

// errors

class AppError extends Error {
  constructor(
    message: string,
    public statusCode: number = 400,
    public code: string = "ERROR",
    public details?: any
  ) {
    super(message);
    this.name = "AppError";
  }
}

class ValidErr extends AppError {
  constructor(message: string, details?: any) {
    super(message, 400, "VALIDATION_ERROR", details);
  }
}

class AuthErr extends AppError {
  constructor(message: string = "Unauthorized") {
    super(message, 401, "AUTH_ERROR");
  }
}

class AuthzErr extends AppError {
  constructor(message: string = "Forbidden") {
    super(message, 403, "FORBIDDEN");
  }
}

class NotFoundError extends AppError {
  constructor(message: string = "Not Found") {
    super(message, 404, "NOT_FOUND");
  }
}

class ConflictError extends AppError {
  constructor(message: string) {
    super(message, 409, "CONFLICT");
  }
}

class RateLimitError extends AppError {
  constructor(message: string = "Rate limit exceeded") {
    super(message, 429, "RATE_LIMIT_EXCEEDED");
  }
}

// types

interface User {
  id: string;
  name: string;
  email: string;
  pwd: string;
  role: "user" | "admin";
  verified: boolean;
  disabled: boolean;
  lastLogin?: string;
  failedLogins: number;
  lockedUntil?: string;
  created: string;
  updated: string;
}

interface Post {
  id: string;
  uid: string;
  slug: string;
  title: string;
  body: string;
  sanitizedBody: string;
  tags: string[];
  views: number;
  likes: string[]; // array bc KV doesn't support Sets
  created: string;
  updated: string;
  published: boolean;
  deleted: boolean;
}

interface RefreshSession {
  uid: string;
  expiresAt: number;
  ip: string;
  tokenHash: string;
  userAgent?: string;
  createdAt: number;
}

interface BannedToken {
  token: string;
  expiresAt: number;
}

type EventType = 'user.created' | 'user.login' | 'user.verified' | 'post.created' | 'post.deleted' | 'security.alert' | 'audit.log';

interface Event {
  type: EventType;
  data: any;
  timestamp: string;
  userId?: string;
  ip?: string;
}

interface Services {
  // see below
  users: any;
  posts: any;
  auth: any;
}

interface Ctx {
  user?: User;
  body?: any;
  requestId?: string;
  services: Services;
}

type Fn = (req: Request, next: () => Promise<Response>, ctx: Ctx) => Promise<Response>;

// setup

// events
type EventCallback = (data?: any) => void;

class EventBus {
  private listeners: Map<string, EventCallback[]> = new Map();

  on(event: string, callback: EventCallback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  }

  emit(event: string, data?: any) {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach((cb) => cb(data));
    }
  }
}

const eventBus = new EventBus();

// persistent storage
let kv: Deno.Kv;

const initKv = async () => {
  kv = await Deno.openKv();
};

// in-memory slug locks
const slugLocks = new Map<string, boolean>();

const acquire_lock = async (key: string, timeout = 5000): Promise<boolean> => {
  const start = Date.now();
  while (slugLocks.has(key)) {
    if (Date.now() - start > timeout) return false;
    await new Promise((r) => setTimeout(r, 100));
  }
  slugLocks.set(key, true);
  return true;
};

const release_lock = (key: string) => {
  slugLocks.delete(key);
};

// services

class UserService {
  constructor(private kv: Deno.Kv) { }

  async findById(id: string): Promise<User | null> {
    const res = await this.kv.get<User>(["users", id]);
    return res.value;
  }

  async findByEmail(email: string): Promise<User | null> {
    const res = await this.kv.get<string>(["users_by_email", email]);
    if (!res.value) return null;
    return this.findById(res.value);
  }

  async create(data: { name: string; email: string; pwd: string }): Promise<User> {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const user: User = {
      id,
      name: data.name,
      email: data.email,
      pwd: data.pwd,
      role: "user",
      verified: false,
      disabled: false,
      failedLogins: 0,
      created: now,
      updated: now,
    };

    const atomic = this.kv.atomic();
    const res = await atomic
      .check({ key: ["users_by_email", user.email], versionstamp: null })
      .set(["users", user.id], user)
      .set(["users_by_email", user.email], user.id)
      .commit();

    if (!res.ok) {
      throw new ConflictError("Email already exists");
    }

    eventBus.emit('user.created', { id: user.id, email: user.email, timestamp: now });
    return user;
  }

  async update(id: string, updates: Partial<User>): Promise<User> {
    const user = await this.findById(id);
    if (!user) throw new NotFoundError("User not found");

    const updatedUser = { ...user, ...updates, updated: new Date().toISOString() };
    await this.kv.set(["users", id], updatedUser);
    return updatedUser;
  }

  async findAll(params: { page: number; limit: number; q?: string }): Promise<{ data: Partial<User>[]; meta: any }> {
    const users: User[] = [];
    const iter = this.kv.list<User>({ prefix: ["users"] });

    for await (const entry of iter) {
      const user = entry.value;
      if (!user.disabled) {
        if (params.q) {
          const q = params.q.toLowerCase();
          if (!user.name.toLowerCase().includes(q) && !user.email.toLowerCase().includes(q)) {
            continue;
          }
        }
        users.push(user);
      }
    }

    const total = users.length;
    const start = (params.page - 1) * params.limit;
    const slice = users.slice(start, start + params.limit).map(strip_sensitive);

    return {
      data: slice,
      meta: { page: params.page, limit: params.limit, total, pages: Math.ceil(total / params.limit) }
    };
  }
}

class PostService {
  constructor(private kv: Deno.Kv) { }

  async findById(id: string): Promise<Post | null> {
    const res = await this.kv.get<Post>(["posts", id]);
    return res.value;
  }

  async create(userId: string, data: { title: string; body: string; tags: string[]; published: boolean; sanitizedBody: string }): Promise<Post> {
    const slug = this.slugify(data.title);
    let finalSlug = slug;
    let counter = 1;

    // make slug
    // todo: distributed locks


    while (true) {
      const existing = await this.kv.get(["slugs", finalSlug]);
      if (!existing.value) break;
      finalSlug = `${slug}-${counter}`;
      counter++;
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const post: Post = {
      id,
      uid: userId,
      slug: finalSlug,
      title: data.title,
      body: data.body,
      sanitizedBody: data.sanitizedBody,
      tags: data.tags,
      views: 0,
      likes: [],
      created: now,
      updated: now,
      published: data.published,
      deleted: false,
    };

    const atomic = this.kv.atomic();
    atomic
      .check({ key: ["slugs", finalSlug], versionstamp: null })
      .set(["posts", id], post)
      .set(["slugs", finalSlug], id)
      .set(["posts_by_user", userId, id], id)
      .set(["posts_by_created", now, id], id); // time index

    for (const tag of data.tags) {
      atomic.set(["posts_by_tag", tag, id], id);
    }

    const res = await atomic.commit();
    if (!res.ok) {
      throw new Error("Failed to create post (slug collision), please try again");
    }

    eventBus.emit('post.created', { id, slug: finalSlug, timestamp: now, userId });
    return post;
  }

  async update(id: string, userId: string, data: Partial<Post>, isAdmin: boolean): Promise<Post> {
    const post = await this.findById(id);
    if (!post || post.deleted) throw new NotFoundError("Post not found");
    if (post.uid !== userId && !isAdmin) throw new AuthzErr();

    const updatedPost = { ...post, ...data, updated: new Date().toISOString() };

    // reindex tags
    if (data.tags) {
      const oldTags = new Set(post.tags);
      const newTags = new Set(data.tags);

      const atomic = this.kv.atomic();
      atomic.set(["posts", id], updatedPost);

      for (const tag of post.tags) {
        if (!newTags.has(tag)) atomic.delete(["posts_by_tag", tag, id]);
      }
      for (const tag of data.tags) {
        if (!oldTags.has(tag)) atomic.set(["posts_by_tag", tag, id], id);
      }

      await atomic.commit();
    } else {
      await this.kv.set(["posts", id], updatedPost);
    }

    return updatedPost;
  }

  async delete(id: string, userId: string, isAdmin: boolean): Promise<void> {
    const post = await this.findById(id);
    if (!post || post.deleted) throw new NotFoundError("Post not found");
    if (post.uid !== userId && !isAdmin) throw new AuthzErr();

    post.deleted = true;
    post.updated = new Date().toISOString();

    await this.kv.set(["posts", id], post);




    // keep slugs reserved

    eventBus.emit('post.deleted', { id, timestamp: new Date().toISOString(), userId });
  }

  async like(id: string, userId: string): Promise<{ likes: number; liked: boolean }> {
    const post = await this.findById(id);
    if (!post || post.deleted) throw new NotFoundError("Post not found");

    const likesSet = new Set(post.likes);
    const hasLiked = likesSet.has(userId);

    if (hasLiked) {
      likesSet.delete(userId);
    } else {
      likesSet.add(userId);
    }

    post.likes = Array.from(likesSet);
    await this.kv.set(["posts", id], post);

    return { likes: post.likes.length, liked: !hasLiked };
  }

  async findAll(params: { page: number; limit: number; uid?: string; tag?: string; q?: string }): Promise<{ data: Post[]; meta: any }> {
    // kv = limited querying
    // scan approach



    const { page, limit, uid, tag, q } = params;
    const posts: Post[] = [];

    // strategy:
    //   user -- posts_by_user
    //   tag -- posts_by_tag
    //   default -- posts_by_created
    //   filter deleted
    //   paginate

    let iter;
    if (uid) {
      iter = this.kv.list({ prefix: ["posts_by_user", uid] });
    } else if (tag) {
      iter = this.kv.list({ prefix: ["posts_by_tag", tag] });
    } else {
      iter = this.kv.list({ prefix: ["posts_by_created"] }, { reverse: true });
    }

    // fixme: slow for deep pages
    // But sufficient for this demo.

    for await (const entry of iter) {
      const postId = entry.value as string;
      const post = await this.findById(postId);

      if (post && !post.deleted) {
        if (q) {
          if (!post.title.toLowerCase().includes(q) && !post.body.toLowerCase().includes(q)) {
            continue;
          }
        }
        posts.push(post);
        // optimizing: if no Q, we can stop after limit + offset
        // but with Q, need to scan.
      }
    }

    // sort by created desc if not using the main index
    if (uid || tag) {
      posts.sort((a, b) => b.created.localeCompare(a.created));
    }

    const total = posts.length;
    const start = (page - 1) * limit;
    const data = posts.slice(start, start + limit);

    return {
      data,
      meta: { page, limit, total, pages: Math.ceil(total / limit) }
    };
  }

  private slugify(text: string): string {
    return text
      .toLowerCase()
      .replace(/[^\w\s-]/g, "")
      .replace(/\s+/g, "-")
      .replace(/-+/g, "-")
      .trim();
  }
}

const make_token = async (userId: string, csrfToken: string): Promise<string> => {
  const payload = {
    sub: userId,
    exp: Math.floor(Date.now() / 1000) + token_exp,
    type: "access",
    jti: id(),
    csrf: await hash_token(csrfToken), // bind CSRF token to JWT
  };
  return await create({ alg: "HS512", typ: "JWT" }, payload, jwt_key);
};

const check_token = async (token: string): Promise<any> => {
  try {
    const payload = await verifyJwt(token, jwt_key);

    // robust validation
    if (!payload || typeof payload !== 'object') return null;
    if (!payload.jti || typeof payload.jti !== 'string') return null;
    if (!payload.exp || typeof payload.exp !== 'number') return null;
    if (payload.exp * 1000 < Date.now()) return null;
    if (payload.type !== "access") return null;
    if (!payload.sub || typeof payload.sub !== 'string') return null;

    // check JTI blacklist in KV
    const blacklisted = await kv.get(["blacklist", payload.jti]);
    if (blacklisted.value) return null;

    return payload;
  } catch {
    return null;
  }
};

const add_blacklist = async (jti: string, expiresAt: number): Promise<void> => {
  // store JTI instead of full token hash for efficiency
  const ttl = Math.max(0, expiresAt - Date.now());
  if (ttl > 0) {
    await kv.set(["blacklist", jti], { jti, expiresAt }, { expireIn: ttl });
  }
};

class AuthService {
  constructor(
    private kv: Deno.Kv,
    private userService: UserService
  ) { }

  async login(email: string, pwd: string, ip: string, ua: string): Promise<{ accessToken: string; refreshToken: string; csrfToken: string; user: User }> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      await random_delay();
      throw new AuthErr("Invalid credentials");
    }

    if (user.disabled) throw new AuthzErr("Account disabled");

    if (check_locked(user)) {
      throw new AuthzErr("Account temporarily locked");
    }

    const valid = await verify_password(pwd, user.pwd);
    if (!valid) {
      await this.handleFailedLogin(user);
      throw new AuthErr("Invalid credentials");
    }

    await this.userService.update(user.id, {
      failedLogins: 0,
      lockedUntil: undefined,
      lastLogin: new Date().toISOString()
    });

    return this.createSession(user, ip, ua);
  }

  async refresh(token: string, ip: string, ua: string): Promise<{ accessToken: string; refreshToken: string; csrfToken: string }> {
    const tokenHash = await hash_token(token);
    const sessionRes = await this.kv.get<RefreshSession>(["sessions", tokenHash]);
    const session = sessionRes.value;

    if (!session || session.expiresAt < Date.now()) {
      if (session) await this.kv.delete(["sessions", tokenHash]);
      throw new AuthErr("Invalid or expired refresh token");
    }

    if (bind_ip && session.ip !== ip) {
      await this.kv.delete(["sessions", tokenHash]);
      throw new AuthzErr("IP mismatch detected");
    }

    const user = await this.userService.findById(session.uid);
    if (!user || user.disabled) throw new AuthErr("User not found or disabled");

    // rotating token
    await this.kv.delete(["sessions", tokenHash]);
    await this.kv.delete(["sessions_by_user", user.id, tokenHash]);

    const result = await this.createSession(user, ip, ua);
    return { accessToken: result.accessToken, refreshToken: result.refreshToken, csrfToken: result.csrfToken };
  }

  async logout(token: string): Promise<void> {
    const tokenHash = await hash_token(token);
    const sessionRes = await this.kv.get<RefreshSession>(["sessions", tokenHash]);
    if (sessionRes.value) {
      await this.kv.delete(["sessions", tokenHash]);
      await this.kv.delete(["sessions_by_user", sessionRes.value.uid, tokenHash]);
    }
  }

  async pwd_reset(email: string): Promise<void> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      // don't reveal user existence
      await random_delay();
      return;
    }

    const resetToken = refresh_token();
    const tokenHash = await hash_token(resetToken);

    // store reset token for 15 minutes
    await this.kv.set(["password_reset", tokenHash], user.id, { expireIn: 900000 });

    // token stored in KV, will be sent via email service in production
    // todo: Integrate with email service (SendGrid, Postmark, etc.)
    console.log(`[SECURITY] Password reset requested for user ${user.id}`);
  }

  async reset_password(token: string, newPwd: string): Promise<void> {
    const tokenHash = await hash_token(token);
    const userIdRes = await this.kv.get<string>(["password_reset", tokenHash]);

    if (!userIdRes.value) {
      throw new AuthErr("Invalid or expired reset token");
    }

    const userId = userIdRes.value;
    const user = await this.userService.findById(userId);
    if (!user) throw new AuthErr("User not found");

    const hashedPassword = await hash_password(newPwd);
    await this.userService.update(userId, { pwd: hashedPassword });

    // invalidate all sessions
    await this.invalidateAllUserSessions(userId);

    // delete used token
    await this.kv.delete(["password_reset", tokenHash]);
  }

  async invalidateAllUserSessions(userId: string): Promise<void> {
    const iter = this.kv.list({ prefix: ["sessions_by_user", userId] });
    for await (const entry of iter) {
      const tokenHash = entry.key[2] as string;
      await this.kv.delete(["sessions", tokenHash]);
      await this.kv.delete(entry.key);
    }
  }

  async listUserSessions(userId: string): Promise<RefreshSession[]> {
    const sessions: RefreshSession[] = [];
    const iter = this.kv.list<string>({ prefix: ["sessions_by_user", userId] });
    for await (const entry of iter) {
      const tokenHash = entry.value;
      const sessionRes = await this.kv.get<RefreshSession>(["sessions", tokenHash]);
      if (sessionRes.value && sessionRes.value.expiresAt > Date.now()) {
        sessions.push(sessionRes.value);
      } else if (sessionRes.value) {
        // clean up expired session
        await this.kv.delete(["sessions", tokenHash]);
        await this.kv.delete(entry.key);
      }
    }
    return sessions;
  }

  async revokeSession(userId: string, tokenHashToRevoke: string): Promise<void> {
    const sessionRes = await this.kv.get<RefreshSession>(["sessions", tokenHashToRevoke]);
    if (!sessionRes.value || sessionRes.value.uid !== userId) {
      throw new NotFoundError("Session not found or not authorized");
    }
    await this.kv.delete(["sessions", tokenHashToRevoke]);
    await this.kv.delete(["sessions_by_user", userId, tokenHashToRevoke]);
  }

  private async createSession(user: User, ip: string, ua: string) {
    const csrfToken = refresh_token();
    const accessToken = await make_token(user.id, csrfToken);
    const refreshToken = refresh_token();
    const tokenHash = await hash_token(refreshToken);

    const session: RefreshSession = {
      uid: user.id,
      expiresAt: Date.now() + refresh_exp * 1000,
      ip,
      tokenHash,
      userAgent: ua,
      createdAt: Date.now(),
    };

    // securing to enforce max_sessions with atomic lock
    const lockKey = `sessions_prune:${user.id}`;
    try {
      await acquire_lock(lockKey);

      const iter = this.kv.list({ prefix: ["sessions_by_user", user.id] });
      const entries: { key: unknown[]; value: string }[] = [];
      for await (const entry of iter) {
        entries.push({ key: entry.key as unknown[], value: entry.value as string });
      }

      if (entries.length >= max_sessions) {
        // fetch session objects to sort by createdAt
        const sessionsWithMeta: { tokenHash: string; createdAt: number }[] = [];
        for (const e of entries) {
          const th = e.key[2] as string;
          const s = await this.kv.get<RefreshSession>(["sessions", th]);
          if (s.value) sessionsWithMeta.push({ tokenHash: th, createdAt: s.value.createdAt ?? 0 });
        }

        // sort by oldest first
        sessionsWithMeta.sort((a, b) => a.createdAt - b.createdAt);

        // remove oldest sessions to make room
        const toRemoveCount = (sessionsWithMeta.length - max_sessions) + 1;
        const toRemove = sessionsWithMeta.slice(0, toRemoveCount);
        for (const rem of toRemove) {
          await this.kv.delete(["sessions", rem.tokenHash]);
          await this.kv.delete(["sessions_by_user", user.id, rem.tokenHash]);
        }
      }
    } catch (e) {
      console.error(`[${user.id}] Session pruning failed`);
    } finally {
      release_lock(lockKey);
    }

    await this.kv.set(["sessions", tokenHash], session);
    await this.kv.set(["sessions_by_user", user.id, tokenHash], tokenHash);

    return { accessToken, refreshToken, csrfToken, user };
  }

  private async handleFailedLogin(user: User) {
    const failedLogins = user.failedLogins + 1;
    let lockedUntil = user.lockedUntil;

    if (failedLogins >= max_fails) {
      lockedUntil = new Date(Date.now() + lockout_time).toISOString();
    }

    await this.userService.update(user.id, { failedLogins, lockedUntil });
  }
}


// schemas

// min 8 chars, mixed case, number and symbol
const pwd_pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// search query validation: alphanumeric, spaces, some special chars, max 100 chars
const search_rules = z.string().max(100).regex(/^[a-zA-Z0-9\s-_.@]+$/).optional();

// UUID validation 
const uuid_rules = z.string().uuid();

const register_rules = z.object({
  name: z.string().min(2).max(100).trim(),
  email: z.string().email().toLowerCase(),
  pwd: z.string().min(8).max(100).refine(
    (pwd) => pwd_pattern.test(pwd),
    {
      message: "Password must contain at least 1 uppercase, 1 lowercase, 1 number, and 1 special character"
    }
  ),
});

const login_rules = z.object({
  email: z.string().email().toLowerCase(),
  pwd: z.string().min(1),
});

const postSchema = z.object({
  title: z.string().min(1).max(200).trim(),
  body: z.string().min(1).max(50000),
  tags: z.array(z.string().trim().toLowerCase().max(50)).max(10).optional().default([]),
  published: z.boolean().optional().default(false),
});

const post_rules = z.object({
  title: z.string().min(1).max(200).trim().optional(),
  body: z.string().min(1).max(50000).optional(),
  tags: z.array(z.string().trim().toLowerCase().max(50)).max(10).optional(),
  published: z.boolean().optional(),
});

const user_rules = z.object({
  name: z.string().min(2).max(100).trim().optional(),
  email: z.string().email().toLowerCase().optional(),
  pwd: z.string().min(8).max(100).refine(
    (pwd) => pwd_pattern.test(pwd),
    {
      message: "Password must contain at least 1 uppercase, 1 lowercase, 1 number, and 1 special character"
    }
  ).optional(),
});

const page_rules = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(10),
}).refine((data) => (data.page - 1) * data.limit <= 10000, {
  message: "Offset too large (max 10000)",
});

// utils

const id = (): string => crypto.randomUUID();
const now = (): string => new Date().toISOString();

// pwd utils
const hash_password = async (pwd: string) => {
  const salt = await bcrypt.genSalt(bcrypt_rounds);
  return await bcrypt.hash(pwd, salt);
};

const verify_password = async (pwd: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(pwd, hash);
};

const hash_token = async (token: string): Promise<string> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
};

// timing-safe csrf check
const safe_compare = (a: string, b: string): boolean => {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
};

const refresh_token = (): string =>
  Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

// html utils
const sanitize_html = (html: string): string => {
  const doc = new DOMParser().parseFromString(html, "text/html");
  if (!doc) return "";
  const dangerousTags = ["script", "iframe", "object", "embed", "link", "style", "base"];
  dangerousTags.forEach(tag => {
    const elements = doc.querySelectorAll(tag);
    elements.forEach((el: any) => el.remove());
  });

  // remove all event handlers from remaining elements
  const allElements = doc.querySelectorAll("*");
  allElements.forEach((el: any) => {
    if (el.attributes) {
      Array.from(el.attributes).forEach((attr: any) => {
        if (attr.name.toLowerCase().startsWith("on")) {
          el.removeAttribute(attr.name);
        }
        // remove javascript: and data: URLs
        if (["href", "src", "action"].includes(attr.name.toLowerCase())) {
          const value = attr.value.toLowerCase().trim();
          if (value.startsWith("javascript:") || value.startsWith("data:")) {
            el.removeAttribute(attr.name);
          }
        }
      });
    }
  });

  return doc.textContent || "";
};

const slugify = (text: string): string =>
  text
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .trim();

const strip_sensitive = (user: User) => {
  const { pwd, failedLogins, lockedUntil, ...safe } = user;
  return safe;
};

const json_response = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
    },
  });

const error_response = (msg: string, status = 400): Response =>
  json_response({ error: env === "production" ? "An error occurred" : msg }, status);

const get_ip = (req: Request, use_trust_proxy = trust_proxy): string => {
  if (use_trust_proxy) {
    const forwarded = req.headers.get("x-forwarded-for");
    if (forwarded) return forwarded.split(",")[0].trim();
  }
  return (req as any).conn?.remoteAddr?.hostname || "unknown";
};

// refresh tokens to httponly cookie
const refresh_cookie = (refreshToken: string): string => {
  const secure_flag = env === "production" ? "; Secure" : "";
  const expires_date = new Date(Date.now() + refresh_exp * 1000).toUTCString();
  return `refresh_token=${refreshToken}; HttpOnly; SameSite=Strict; Path=/; Expires=${expires_date}${secure_flag}`;
};

// pull token from cookie
const read_cookie = (req: Request): string | null => {
  const cookie_header = req.headers.get("cookie");
  if (!cookie_header) return null;
  const match = cookie_header.match(/refresh_token=([^;]+)/);
  return match ? match[1] : null;
};

const get_agent = (req: Request): string => {
  return req.headers.get("user-agent") || "unknown";
};





const parseBody = async (req: Request): Promise<any> => {
  try {
    const text = await req.text();
    if (text.length > max_body) {
      throw new Error("Body too large");
    }
    return JSON.parse(text);
  } catch {
    return null;
  }
};

// pwd reset / email verification

const pwd_reset = async (req: Request, ctx: Ctx) => {
  const { email } = ctx.body || {};
  if (!email || typeof email !== 'string') {
    return error_response("Email required", 400);
  }

  await ctx.services.auth.pwd_reset(email);
  return json_response({ message: "If an account exists with this email, a password reset link has been sent." });
};

const reset_password = async (req: Request, ctx: Ctx) => {
  const { token, newPwd } = ctx.body || {};

  if (!token || typeof token !== 'string') return error_response("Token required", 400);
  if (!newPwd || typeof newPwd !== 'string') return error_response("New password required", 400);

  // validate password strenght
  if (!pwd_pattern.test(newPwd)) {
    return error_response("Password must contain at least 1 uppercase, 1 lowercase, 1 number, and 1 special character", 400);
  }

  try {
    await ctx.services.auth.reset_password(token, newPwd);
    return json_response({ message: "Password reset successful. You can now login with your new password." });
  } catch (e) {
    if (e instanceof AuthErr) return error_response(e.message, 400);
    throw e;
  }
};

const verify_email = async (req: Request, ctx: Ctx) => {
  const url = new URL(req.url);
  const token = url.searchParams.get("token");

  if (!token) return error_response("Token required", 400);

  try {
    await ctx.services.auth.verify_email(token);
    return json_response({ message: "Email verified successfully. You can now login." });
  } catch (e) {
    if (e instanceof AuthErr) return error_response(e.message, 400);
    throw e;
  }
};


const check_locked = (user: User): boolean => {
  if (!user.lockedUntil) return false;
  const lockTime = new Date(user.lockedUntil).getTime();
  if (lockTime > Date.now()) return true;

  // expired lock, reset
  user.lockedUntil = undefined;
  user.failedLogins = 0;
  return false;
};

// prevent timing leaks  
const random_delay = async (): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, 100 + Math.random() * 50));
};



// middleware

const errorHandler: Fn = async (req, next, ctx) => {
  try {
    return await next();
  } catch (e) {
    if (e instanceof AppError) {
      return json_response({
        error: env === "production" ? "An error occurred" : e.message,
        code: e.code,
        details: env === "development" ? e.details : undefined,
        requestId: ctx.requestId,
      }, e.statusCode);
    }

    console.error(`[${ctx.requestId}] Unhandled error:`, e);
    return error_response("Internal server error", 500);
  }
};

const requestId: Fn = async (req, next, ctx) => {
  ctx.requestId = crypto.randomUUID();
  const res = await next();
  const headers = new Headers(res.headers);
  headers.set("X-Request-ID", ctx.requestId);
  return new Response(res.body, { status: res.status, headers });
};

const block_override: Fn = async (req, next, ctx) => {
  if (req.headers.has("x-http-method-override")) {
    return error_response("Method override not allowed", 405);
  }
  return next();
};

const req_timeout: Fn = async (req, next, ctx) => {
  const timeout = 10000; // 10s
  let timer: number;

  const timeoutPromise = new Promise<Response>((resolve) => {
    timer = setTimeout(() => {
      resolve(error_response("Request timeout", 408));
    }, timeout);
  });

  try {
    const res = await Promise.race([next(), timeoutPromise]);
    clearTimeout(timer!);
    return res;
  } catch (e) {
    clearTimeout(timer!);
    throw e;
  }
};

const add_headers: Fn = async (req, next, ctx) => {
  const res = await next();
  const headers = new Headers(res.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-XSS-Protection", "1; mode=block");
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
  );
  headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()");
  return new Response(res.body, { status: res.status, headers });
};

const cors: Fn = async (req, next, ctx) => {
  const origin = req.headers.get("origin") || "";

  let allowedOrigin = "";
  if (env === "production") {
    allowedOrigin = allowed_origins.includes(origin) ? origin : "";
  } else {
    allowedOrigin = allowed_origins.includes("*") || allowed_origins.includes(origin)
      ? origin || allowed_origins[0]
      : "";
  }

  const res = await next();
  const headers = new Headers(res.headers);

  if (allowedOrigin) {
    headers.set("Access-Control-Allow-Origin", allowedOrigin);
    headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Max-Age", "86400");
    headers.set("Vary", "Origin"); // critical: required for dynamic CORS
  }

  return new Response(res.body, { status: res.status, headers });
};

const log: Fn = async (req, next, ctx) => {
  const t = Date.now();
  const res = await next();
  const uid = ctx.user?.id || "anon";
  const ip = get_ip(req);
  const log = {
    requestId: ctx.requestId,
    method: req.method,
    path: new URL(req.url).pathname,
    status: res.status,
    duration: Date.now() - t,
    user: uid,
    ip,
    timestamp: new Date().toISOString(),
  };
  console.log(JSON.stringify(log));
  return res;
};

const rateLimit: Fn = (() => {
  const requestsByIp = new Map<string, number[]>();
  const requestsByUser = new Map<string, number[]>();

  return async (req, next, ctx) => {
    const ip = get_ip(req);
    const nowTs = Math.floor(Date.now() / 1000);

    // IP-based rate limiting
    const ipHistory = (requestsByIp.get(ip) || []).filter(
      (t) => nowTs - t < rate_window
    );

    if (ipHistory.length >= rate_max) {
      return error_response("Rate limit exceeded", 429);
    }

    ipHistory.push(nowTs);
    requestsByIp.set(ip, ipHistory);

    // user-based rate limiting (if authed)
    if (ctx.user) {
      const userHistory = (requestsByUser.get(ctx.user.id) || []).filter(
        (t) => nowTs - t < rate_window
      );

      if (userHistory.length >= rate_max * 2) {
        return error_response("User rate limit exceeded", 429);
      }

      userHistory.push(nowTs);
      requestsByUser.set(ctx.user.id, userHistory);
    }

    // cleanup periodically
    if (Math.random() < 0.01) {
      requestsByIp.forEach((times, key) => {
        const filtered = times.filter((t) => nowTs - t < rate_window);
        if (filtered.length === 0) requestsByIp.delete(key);
        else requestsByIp.set(key, filtered);
      });
    }

    return next();
  };
})();

const loginRateLimit: Fn = (() => {
  const attempts = new Map<string, number[]>();

  return async (req, next, ctx) => {
    const body = ctx.body;
    if (!body?.email) return next();

    const key = `${get_ip(req)}:${body.email}`;
    const nowTs = Math.floor(Date.now() / 1000);
    const history = (attempts.get(key) || []).filter(
      (t) => nowTs - t < rate_window
    );

    if (history.length >= login_rate_max) {
      return error_response("Too many login attempts", 429);
    }

    history.push(nowTs);
    attempts.set(key, history);

    return next();
  };
})();

const auth: Fn = async (req, next, ctx) => {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return error_response("Unauthorized", 401);
  }

  const token = authHeader.substring(7);
  const payload = await check_token(token);

  if (!payload) {
    return error_response("Token expired or invalid", 401);
  }

  const user = await ctx.services.users.findById(payload.sub);
  if (!user) {
    return error_response("User not found", 401);
  }

  if (user.disabled) {
    return error_response("Account disabled", 403);
  }

  ctx.user = user;
  // store payload for CSRF check
  (ctx as any).jwtPayload = payload;
  return next();
};

const csrfProtection: Fn = async (req, next, ctx) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  if (!ctx.user) {
    // if not authed, CSRF might not apply or handled by auth middleware
    // but if we have public POSTs (like login/register), they don't use this middleware usually.
    // this middleware is for authed sessions.
    return next();
  }

  const csrfHeader = req.headers.get("X-CSRF-Token");
  if (!csrfHeader) {
    return error_response("CSRF token required", 403);
  }

  const jwtPayload = (ctx as any).jwtPayload;
  if (!jwtPayload || !jwtPayload.csrf) {
    // should not happen if auth middleware ran and token has csrf claim
    return error_response("Invalid session state", 403);
  }

  const headerHash = await hash_token(csrfHeader);
  if (!safe_compare(headerHash, jwtPayload.csrf)) {
    return error_response("Invalid CSRF token", 403);
  }

  return next();
};

const admin: Fn = async (_req, next, ctx) => {
  if (!ctx.user || ctx.user.role !== "admin") {
    return error_response("Forbidden", 403);
  }
  return next();
};

const log_audit = (action: string, userId: string, details: unknown) => {
  console.log(`[AUDIT] ${new Date().toISOString()} | User: ${userId} | Action: ${action} | Details: ${JSON.stringify(details)}`);
};

const bodyParser: Fn = async (req, next, ctx) => {
  if (["POST", "PUT", "PATCH"].includes(req.method)) {
    const contentType = req.headers.get("Content-Type");
    if (!contentType || !contentType.includes("application/json")) {
      return error_response("Content-Type must be application/json", 415);
    }

    ctx.body = await parseBody(req);
    if (ctx.body === null) {
      return error_response("Invalid JSON or body too large", 400);
    }
  }
  return next();
};

// routes

const health = (_req: Request, _match: URLPatternResult, ctx: Ctx) => {
  // health
  // admin check for detailed info
  if (!ctx.user || ctx.user.role !== 'admin') {
    return json_response({ ok: true, ts: Date.now() });
  }

  return json_response({
    ok: true,
    ts: Date.now(),
    mem: Deno.memoryUsage(),
    uptime: performance.now(),
    env: env,
  });
};

const register = async (_req: Request, ctx: Ctx) => {
  const parsed = register_rules.safeParse(ctx.body);
  if (!parsed.success) {
    return error_response(parsed.error.errors[0].message);
  }

  const { name, email, pwd } = parsed.data;
  const hashedPwd = await hash_password(pwd);

  try {
    const newUser = await ctx.services.users.create({ name, email, pwd: hashedPwd });
    return json_response(strip_sensitive(newUser), 201);
  } catch (e) {
    if (e instanceof ConflictError) {
      // timing protection
      await random_delay();
      return error_response("Registration failed", 400);
    }
    throw e;
  }
};

const login = async (req: Request, ctx: Ctx) => {
  const parsed = login_rules.safeParse(ctx.body);
  if (!parsed.success) {
    return error_response(parsed.error.errors[0].message);
  }

  const { email, pwd } = parsed.data;
  const clientIp = get_ip(req);
  const userAgent = get_agent(req);

  try {
    const authResult = await ctx.services.auth.login(email, pwd, clientIp, userAgent);

    // httponly cookies (no XSS)
    const cookieHeader = refresh_cookie(authResult.refreshToken);

    return new Response(JSON.stringify({
      accessToken: authResult.accessToken,
      csrfToken: authResult.csrfToken,
      expiresIn: token_exp,
      user: strip_sensitive(authResult.user)
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
        "Set-Cookie": cookieHeader
      }
    });
  } catch (e) {
    if (e instanceof AuthErr) return error_response(e.message, 401);
    if (e instanceof AuthzErr) return error_response(e.message, 403);
    throw e;
  }
};

const refresh = async (req: Request, ctx: Ctx) => {
  const { refreshToken: tokenFromBody } = ctx.body || {};
  const tokenFromCookie = read_cookie(req);

  // cookie preferred, body fallback
  const refreshToken = tokenFromCookie || tokenFromBody;

  if (!refreshToken) {
    return error_response("Refresh token required", 400);
  }

  const clientIp = get_ip(req);
  const userAgent = get_agent(req);

  const rotated = await ctx.services.auth.refresh(refreshToken, clientIp, userAgent);

  // rotating token
  const cookieHeader = refresh_cookie(rotated.refreshToken);

  return new Response(JSON.stringify({
    accessToken: rotated.accessToken,
    csrfToken: rotated.csrfToken,
    expiresIn: token_exp,
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "Set-Cookie": cookieHeader
    }
  });
};

const logout = async (req: Request, ctx: Ctx) => {
  if (!ctx.user) return json_response({ ok: true });

  const authHeader = req.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.substring(7);

    // blacklist jwt
    try {
      const payload = await verifyJwt(token, jwt_key);
      if (payload?.jti) {
        await add_blacklist(payload.jti, (payload.exp || 0) * 1000);
      }
    } catch {
      // already invalid
    }
  }

  const { refreshToken } = ctx.body || {};
  if (refreshToken) {
    await ctx.services.auth.logout(refreshToken);
  }

  return json_response({ ok: true });
};

const me = (_req: Request, ctx: Ctx) => {
  if (!ctx.user) return error_response("Unauthorized", 401);
  return json_response(strip_sensitive(ctx.user));
};

const listSessions = async (_req: Request, ctx: Ctx) => {
  if (!ctx.user) return error_response("Unauthorized", 401);

  const sessions = await ctx.services.auth.listUserSessions(ctx.user.id);
  const sessionsInfo = sessions.map((s: any) => ({
    tokenHash: s.tokenHash,
    ip: s.ip,
    userAgent: s.userAgent,
    createdAt: new Date(s.createdAt).toISOString(),
    expiresAt: new Date(s.expiresAt).toISOString(),
  }));

  return json_response({ sessions: sessionsInfo });
};

const revokeSession = async (_req: Request, ctx: Ctx) => {
  if (!ctx.user) return error_response("Unauthorized", 401);

  const { tokenHash } = ctx.body || {};
  if (!tokenHash || typeof tokenHash !== 'string') {
    return error_response("Token hash required", 400);
  }

  try {
    await ctx.services.auth.revokeSession(ctx.user.id, tokenHash);
    return json_response({ message: "Session revoked successfully" });
  } catch (e) {
    if (e instanceof NotFoundError) return error_response(e.message, 404);
    throw e;
  }
};

const getUsers = async (req: Request, ctx: Ctx) => {
  const url = new URL(req.url);
  const pagination = page_rules.parse({
    page: url.searchParams.get("page") || undefined,
    limit: url.searchParams.get("limit") || undefined,
  });

  const qRaw = url.searchParams.get("q");
  const qParsed = search_rules.safeParse(qRaw);

  if (!qParsed.success) {
    return error_response("Invalid search query", 400);
  }

  const q = qParsed.data?.toLowerCase();

  const result = await ctx.services.users.findAll({
    page: pagination.page,
    limit: pagination.limit,
    q,
  });

  return json_response(result);
};

const getPosts = async (req: Request, ctx: Ctx) => {
  const url = new URL(req.url);
  const pagination = page_rules.parse({
    page: url.searchParams.get("page") || undefined,
    limit: url.searchParams.get("limit") || undefined,
  });

  const uidRaw = url.searchParams.get("uid") || undefined;
  const uidParsed = uidRaw ? uuid_rules.safeParse(uidRaw) : { success: true, data: undefined };
  if (!uidParsed.success) return error_response("Invalid user ID", 400);

  const tagRaw = url.searchParams.get("tag") || undefined;
  const tagParsed = search_rules.safeParse(tagRaw); // tags are similar to search terms
  if (!tagParsed.success) return error_response("Invalid tag", 400);

  const searchRaw = url.searchParams.get("q") || undefined;
  const searchParsed = search_rules.safeParse(searchRaw);
  if (!searchParsed.success) return error_response("Invalid search query", 400);

  const result = await ctx.services.posts.findAll({
    page: pagination.page,
    limit: pagination.limit,
    uid: uidParsed.data,
    tag: tagParsed.data?.toLowerCase(),
    q: searchParsed.data?.toLowerCase(),
  });

  return json_response(result);
};

const addPost = async (_req: Request, ctx: Ctx) => {
  if (!ctx.user) return error_response("Unauthorized", 401);

  const parsed = postSchema.safeParse(ctx.body);
  if (!parsed.success) {
    return error_response(parsed.error.errors[0].message);
  }

  const { title, body, tags, published } = parsed.data;
  const sanitizedBody = sanitize_html(body);

  try {
    const post = await ctx.services.posts.create(ctx.user.id, {
      title,
      body,
      tags,
      published,
      sanitizedBody,
    });
    return json_response({ ...post, likes: [] }, 201);
  } catch (e) {
    return error_response((e as Error).message, 500);
  }
};

const getPost = async (_req: Request, match: URLPatternResult, ctx: Ctx) => {
  const postId = match.pathname.groups.id!;

  if (!uuid_rules.safeParse(postId).success) {
    return error_response("Invalid post ID format", 400);
  }

  const post = await ctx.services.posts.findById(postId);

  if (!post || post.deleted) {
    return error_response("Post not found", 404);
  }

  return json_response({ ...post, likes: post.likes });
};

const updatePost = async (
  _req: Request,
  match: URLPatternResult,
  ctx: Ctx
) => {
  if (!ctx.user) return error_response("Unauthorized", 401);

  const postId = match.pathname.groups.id!;
  if (!uuid_rules.safeParse(postId).success) {
    return error_response("Invalid post ID format", 400);
  }

  const parsed = post_rules.safeParse(ctx.body);
  if (!parsed.success) {
    return error_response(parsed.error.errors[0].message);
  }

  try {
    const isAdmin = ctx.user.role === 'admin';
    const post = await ctx.services.posts.update(postId, ctx.user.id, parsed.data, isAdmin);

    if (isAdmin) {
      log_audit("UPDATE_POST", ctx.user.id, { postId, updates: parsed.data });
    }

    return json_response({ ...post, likes: post.likes });
  } catch (e) {
    if (e instanceof NotFoundError) return error_response(e.message, 404);
    if (e instanceof AuthzErr) return error_response(e.message, 403);
    throw e;
  }
};

const deletePost = async (_req: Request, match: URLPatternResult, ctx: Ctx) => {
  if (!ctx.user) return error_response("Unauthorized", 401);

  const postId = match.pathname.groups.id!;
  if (!uuid_rules.safeParse(postId).success) {
    return error_response("Invalid post ID format", 400);
  }

  try {
    const isAdmin = ctx.user.role === 'admin';
    await ctx.services.posts.delete(postId, ctx.user.id, isAdmin);

    if (isAdmin) {
      log_audit("DELETE_POST", ctx.user.id, { postId });
    }

    return new Response(null, { status: 204 });
  } catch (e) {
    if (e instanceof NotFoundError) return error_response(e.message, 404);
    if (e instanceof AuthzErr) return error_response(e.message, 403);
    throw e;
  }
};

const likePost = async (_req: Request, match: URLPatternResult, ctx: Ctx) => {
  if (!ctx.user) return error_response("Unauthorized", 401);

  const postId = match.pathname.groups.id!;
  if (!uuid_rules.safeParse(postId).success) {
    return error_response("Invalid post ID format", 400);
  }

  try {
    const result = await ctx.services.posts.like(postId, ctx.user.id);
    return json_response(result);
  } catch (e) {
    if (e instanceof NotFoundError) return error_response(e.message, 404);
    throw e;
  }
};

const stats = async (_req: Request, ctx: Ctx) => {
  if (!ctx.user || ctx.user.role !== 'admin') return error_response("Unauthorized", 401);
  // await required for async function
  await Promise.resolve();

  return json_response({
    users: { total: "N/A (KV)" },
    posts: { total: "N/A (KV)" },
    sessions: "N/A (KV)",
    blacklistedTokens: "N/A (KV)",
  });
};

// routing

interface Route {
  method: string;
  pattern: URLPattern;
  handler: (req: Request, match: URLPatternResult, ctx: Ctx) => Promise<Response> | Response;
  middleware?: Fn[];
}

const routes: Route[] = [
  {
    method: "GET",
    pattern: new URLPattern({ pathname: "/v1/health" }),
    handler: health,
  },
  {
    method: "POST",
    pattern: new URLPattern({ pathname: "/v1/auth/register" }),
    handler: (req, _, ctx) => register(req, ctx),
    middleware: [loginRateLimit], // Fix 9
  },
  {
    method: "GET",
    pattern: new URLPattern({ pathname: "/v1/auth/verify" }),
    handler: (req, _, ctx) => verify_email(req, ctx),
  },
  {
    method: "POST",
    pattern: new URLPattern({ pathname: "/v1/auth/login" }),
    handler: (req, _, ctx) => login(req, ctx),
    middleware: [loginRateLimit],
  },
  {
    method: "POST",
    pattern: new URLPattern({ pathname: "/v1/auth/refresh" }),
    handler: (req, _, ctx) => refresh(req, ctx),
  },
  {
    method: "POST",
    pattern: new URLPattern({ pathname: "/v1/auth/password-reset-request" }),
    handler: (req, _, ctx) => pwd_reset(req, ctx),
    middleware: [loginRateLimit],
  },
  {
    method: "POST",
    pattern: new URLPattern({ pathname: "/v1/auth/password-reset" }),
    handler: (req, _, ctx) => reset_password(req, ctx),
    middleware: [loginRateLimit],
  },
  {
    method: "POST",
    pattern: new URLPattern({ pathname: "/v1/auth/logout" }),
    handler: (req, _, ctx) => logout(req, ctx),
    middleware: [auth, csrfProtection],
  },
  {
    method: "GET",
    pattern: new URLPattern({ pathname: "/v1/auth/me" }),
    handler: (req, _, ctx) => me(req, ctx),
    middleware: [auth],
  },
  {
    method: "GET",
    pattern: new URLPattern({ pathname: "/v1/users" }),
    handler: (req, _, ctx) => getUsers(req, ctx),
    middleware: [auth],
  },
  {
    method: "GET",
    pattern: new URLPattern({ pathname: "/v1/posts" }),
    handler: (req, _, ctx) => getPosts(req, ctx),
  },
  {
    method: "POST",
    pattern: new URLPattern({ pathname: "/v1/posts" }),
    handler: (req, _, ctx) => addPost(req, ctx),
    middleware: [auth, csrfProtection],
  },
  {
    method: "GET",
    pattern: new URLPattern({ pathname: "/v1/posts/:id" }),
    handler: (req, match, ctx) => getPost(req, match, ctx),
  },
  {
    method: "PUT",
    pattern: new URLPattern({ pathname: "/v1/posts/:id" }),
    handler: (req, match, ctx) => updatePost(req, match, ctx),
    middleware: [auth, csrfProtection],
  },
  {
    method: "DELETE",
    pattern: new URLPattern({ pathname: "/v1/posts/:id" }),
    handler: (req, match, ctx) => deletePost(req, match, ctx),
    middleware: [auth, csrfProtection],
  },
  {
    method: "POST",
    pattern: new URLPattern({ pathname: "/v1/posts/:id/like" }),
    handler: (req, match, ctx) => likePost(req, match, ctx),
    middleware: [auth, csrfProtection],
  },
  {
    method: "GET",
    pattern: new URLPattern({ pathname: "/v1/stats" }),
    handler: (req, _, ctx) => stats(req, ctx),
    middleware: [auth, admin],
  },
];

// main handler

const create_handler = (services: Services) => async (req: Request): Promise<Response> => {
  await Promise.resolve(); // satisfy require-await
  if (req.method === "OPTIONS") {
    const origin = req.headers.get("origin") || "";
    let allowedOrigin = "";

    if (env === "production") {
      allowedOrigin = allowed_origins.includes(origin) ? origin : "";
    } else {
      allowedOrigin = allowed_origins.includes("*") || allowed_origins.includes(origin)
        ? origin || allowed_origins[0]
        : "";
    }

    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": allowedOrigin || allowed_origins[0],
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  const _url = new URL(req.url);
  let matchedRoute: Route | null = null;
  let match: URLPatternResult | null = null;

  for (const route of routes) {
    if (route.method !== req.method) continue;
    const m = route.pattern.exec(req.url);
    // console.log(`[DEBUG] Checking ${route.method} pattern against ${req.url}: ${!!m}`);
    if (m) {
      matchedRoute = route;
      match = m;
      break;
    }
  }

  if (!matchedRoute) {
    // method not allowed check
    for (const route of routes) {
      const m = route.pattern.exec(req.url);
      if (m) {
        return error_response("Method not allowed", 405);
      }
    }
    return error_response("Not found", 404);
  }

  const ctx: Ctx = { services };
  const middleware = [
    errorHandler,
    requestId,
    block_override, // prevent method override
    req_timeout,
    add_headers,
    cors,
    log,
    bodyParser,
    rateLimit,
    ...(matchedRoute.middleware || []),
  ];

  let handler = async () => await matchedRoute!.handler(req, match!, ctx);

  for (let i = middleware.length - 1; i >= 0; i--) {
    const mid = middleware[i];
    const next = handler;
    handler = async () => await mid(req, next, ctx);
  }

  return handler();
};

// startup

const startup = async () => {
  console.log("Starting Deno API Server...");
  console.log(`Environment: ${env}`);

  try {
    // validate config
    check_secret(jwt_secret || "");
    console.log(`JWT Secret:Validated`);
  } catch (e) {
    console.error(`❌ ${(e as Error).message}`);
    Deno.exit(1);
  }

  console.log(`CORS Origins: ${allowed_origins.join(", ")}`);
  console.log(`Access Token TTL: ${token_exp}s`);
  console.log(`Refresh Token TTL: ${refresh_exp}s`);
  console.log(`Bcrypt Rounds: ${bcrypt_rounds}`);
  console.log(`Max Body Size: ${max_body / 1024 / 1024}MB`);
  console.log(`Rate Limit: ${rate_max} requests per ${rate_window}s`);
  console.log(`Account Lockout: ${max_fails} failed attempts`);
  console.log(`IP Binding: ${bind_ip ? "✅ Enabled" : "⚠️  Disabled"}`);
  console.log(`Max Posts/User: ${max_user_posts}`);
  console.log(`Max Posts/Tag: ${max_tag_posts}`);
  console.log(`Max Sessions/User: ${max_sessions}`);
  console.log(`Max Blacklist Size: ${max_blacklist}`);

  await initJwtKey();
  console.log("JWT key initialized");

  await initKv();
  console.log("KV initialized");

  const userService = new UserService(kv);
  const postService = new PostService(kv);
  const authService = new AuthService(kv, userService);

  const services: Services = {
    users: userService,
    posts: postService,
    auth: authService,
  };

  if (env === "development") {
    const adminEmail = Deno.env.get("ADMIN_EMAIL");
    const adminPassword = Deno.env.get("ADMIN_PASSWORD");

    if (adminEmail && adminPassword) {
      try {
        const existing = await userService.findByEmail(adminEmail);
        if (!existing) {
          await userService.create({
            name: "Admin User",
            email: adminEmail,
            pwd: await hash_password(adminPassword),
          });
          const admin = await userService.findByEmail(adminEmail);
          if (admin) {
            await userService.update(admin.id, { role: "admin", verified: true });
            console.log(`Admin user created: ${adminEmail}`);
            // don't log pwds
          }
        } else {
          console.log("Admin user already exists");
        }
      } catch (e) {
        console.error("Failed to create admin user:", e);
      }
    }
  }

  console.log("   POST /auth/login");
  console.log("   POST /auth/refresh");
  console.log("   POST /auth/logout");
  console.log("   GET  /auth/me");
  console.log("   GET  /users");
  console.log("   GET  /posts");
  console.log("   POST /posts");
  console.log("   GET  /posts/:id");
  console.log("   PUT  /posts/:id");
  console.log("   DELETE /posts/:id");
  console.log("   POST /posts/:id/like");
  console.log("   GET  /stats (admin only)");
  console.log("");

  // cleanup stale locks every min
  // setInterval(clean_locks, 60000);

  await serve(create_handler(services), { port: port });
};

startup();

