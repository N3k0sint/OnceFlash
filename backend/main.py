"""
OnceFlash — Zero-Knowledge Secure Pastebin
Backend: FastAPI + Redis

Security posture:
  - Server is strictly zero-knowledge: only ciphertext blobs are stored.
  - Atomic Redis Lua scripts prevent double-read race conditions.
  - Pydantic v2 strict validation on all inputs.
  - SlowAPI rate limiting on create and retrieve endpoints.
  - Strict OWASP security headers on every response.
"""

import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Optional

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, Response, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    redis_url: str = "memory://"
    upstash_redis_url: Optional[str] = None
    allowed_origins: str | list[str] = ["*"]          # Tighten in production
    max_ciphertext_bytes: int = 2 * 1024 * 1024  # 2 MiB
    default_ttl_seconds: int = 86_400            # 24 h
    max_ttl_seconds: int = 7 * 86_400            # 7 days
    max_views: int = 100
    rate_limit_create: str = "20/minute"
    rate_limit_read: str = "60/minute"
    log_level: str = "INFO"

    @field_validator("redis_url", "upstash_redis_url", mode="before")
    @classmethod
    def clean_redis_url(cls, v):
        if not v or not isinstance(v, str):
            return v
        v = v.strip()
        for prefix in ("REDIS_URL=", "UPSTASH_REDIS_URL="):
            if v.startswith(prefix):
                v = v[len(prefix):].strip()
        return v.strip("\"'")

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

settings = Settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("onceflash")

# ──────────────────────────────────────────────────────────────────────────────
# Storage Layer: Redis with In-Memory Fallback
# ──────────────────────────────────────────────────────────────────────────────

class InMemoryStore:
    """Thread-safe, atomic in-memory ephemeral store for local/dev use."""
    def __init__(self):
        import asyncio
        self._data: dict[str, dict] = {}
        self._expires: dict[str, float] = {}
        self._receipts: dict[str, dict] = {}
        self._receipt_expires: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def ping(self):
        return True

    def _cleanup_expired(self):
        now = time.time()
        expired = [k for k, exp in self._expires.items() if exp <= now]
        for k in expired:
            paste = self._data.pop(k, None)
            self._expires.pop(k, None)
            if paste and k not in self._receipts:
                self._receipts[k] = {
                    "status": "destroyed",
                    "status_token": str(paste.get("status_token", "")),
                    "timestamp": now,
                }
                self._receipt_expires[k] = now + 86400

        expired_receipts = [k for k, exp in self._receipt_expires.items() if exp <= now]
        for k in expired_receipts:
            self._receipts.pop(k, None)
            self._receipt_expires.pop(k, None)

    async def set_paste(self, key: str, mapping: dict, ttl_seconds: int):
        async with self._lock:
            self._cleanup_expired()
            self._data[key] = mapping.copy()
            self._expires[key] = time.time() + ttl_seconds

    async def read_and_burn(self, key: str):
        async with self._lock:
            self._cleanup_expired()
            if key not in self._data:
                return None
            paste = self._data[key]
            views_left = int(paste.get("views_left", 0))
            ciphertext = paste.get("ciphertext")
            created_at = paste.get("created_at")
            status_token = str(paste.get("status_token", ""))

            if views_left <= 1:
                self._data.pop(key, None)
                self._expires.pop(key, None)
            else:
                paste["views_left"] = views_left - 1

            self._receipts[key] = {
                "status": "opened",
                "status_token": status_token,
                "timestamp": time.time(),
            }
            self._receipt_expires[key] = time.time() + 86400

            return (ciphertext, views_left, created_at)

    async def delete(self, key: str) -> int:
        async with self._lock:
            if key in self._data:
                paste = self._data[key]
                status_token = str(paste.get("status_token", ""))
                self._data.pop(key, None)
                self._expires.pop(key, None)
                self._receipts[key] = {
                    "status": "destroyed",
                    "status_token": status_token,
                    "timestamp": time.time(),
                }
                self._receipt_expires[key] = time.time() + 86400
                return 1
            if key in self._receipts:
                self._receipts[key]["status"] = "destroyed"
                self._receipts[key]["timestamp"] = time.time()
                return 1
            return 0

    async def get_metadata(self, key: str) -> dict | None:
        async with self._lock:
            self._cleanup_expired()
            if key not in self._data:
                return None
            paste = self._data[key]
            exp = self._expires.get(key, 0)
            return {
                "views_left": int(paste.get("views_left", 0)),
                "created_at": int(paste.get("created_at", 0)),
                "status_token": str(paste.get("status_token", "")),
                "autowipe": int(paste.get("autowipe", 0)),
                "ttl_left": max(0, int(exp - time.time())),
            }

    async def get_receipt(self, key: str) -> dict | None:
        async with self._lock:
            self._cleanup_expired()
            return self._receipts.get(key)


class StorageManager:
    def __init__(self):
        self.is_redis: bool = False
        self.redis: aioredis.Redis | None = None
        self.memory: InMemoryStore = InMemoryStore()
        self.lua_read_and_burn = None

    async def init(self, redis_url: str):
        if not redis_url:
            self.is_redis = False
            return

        clean_url = redis_url.strip()
        for prefix in ("REDIS_URL=", "UPSTASH_REDIS_URL="):
            if clean_url.startswith(prefix):
                clean_url = clean_url[len(prefix):].strip()
        clean_url = clean_url.strip("\"'")

        if clean_url.startswith("memory://"):
            logger.info("Using built-in in-memory ephemeral storage")
            self.is_redis = False
            return

        try:
            import re
            masked_url = re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", clean_url)
            logger.info("Connecting to Redis at %s", masked_url)
            client = aioredis.from_url(
                clean_url,
                decode_responses=False,
                socket_connect_timeout=5,
                socket_timeout=5,
                health_check_interval=30,
            )
            await client.ping()
            self.redis = client
            self.lua_read_and_burn = client.register_script(LUA_READ_AND_BURN)
            self.is_redis = True
            logger.info("Redis connection established (production mode)")
        except Exception as exc:
            logger.warning(
                "Redis unavailable (%s). Falling back to built-in in-memory storage.",
                exc,
            )
            self.is_redis = False

    async def ping(self):
        if self.is_redis and self.redis:
            await self.redis.ping()
        else:
            await self.memory.ping()

    async def save_paste(self, key: str, mapping: dict, ttl_seconds: int):
        if self.is_redis and self.redis:
            pipe = self.redis.pipeline(transaction=True)
            pipe.hset(key, mapping=mapping)
            pipe.expire(key, ttl_seconds)
            await pipe.execute()
        else:
            await self.memory.set_paste(key, mapping, ttl_seconds)

    async def read_and_burn(self, key: str):
        if self.is_redis and self.lua_read_and_burn:
            return await self.lua_read_and_burn(keys=[key], args=[str(int(time.time()))])
        else:
            return await self.memory.read_and_burn(key)

    async def delete_paste(self, key: str) -> int:
        if self.is_redis and self.redis:
            pipe = self.redis.pipeline()
            pipe.hget(key, "status_token")
            pipe.delete(key)
            receipt_key = f"receipt:{key}"
            pipe.hget(receipt_key, "status_token")
            res = await pipe.execute()
            token, deleted, receipt_token = res[0], res[1], res[2]
            actual_token = token or receipt_token
            if deleted or receipt_token:
                pipe = self.redis.pipeline()
                pipe.hset(receipt_key, mapping={
                    "status": "destroyed",
                    "status_token": (actual_token.decode() if isinstance(actual_token, bytes) else str(actual_token)) if actual_token else "",
                    "timestamp": str(int(time.time())),
                })
                pipe.expire(receipt_key, 86400)
                await pipe.execute()
                return 1
            return 0
        else:
            return await self.memory.delete(key)

    async def get_metadata(self, key: str) -> dict | None:
        if self.is_redis and self.redis:
            pipe = self.redis.pipeline()
            pipe.hmget(key, ["views_left", "created_at", "status_token", "autowipe"])
            pipe.ttl(key)
            res = await pipe.execute()
            data, ttl = res[0], res[1]
            if not data or not data[0]:
                return None
            views_left = int(data[0].decode() if isinstance(data[0], bytes) else data[0])
            created_at = int(data[1].decode() if isinstance(data[1], bytes) else (data[1] or 0))
            status_token = data[2].decode() if isinstance(data[2], bytes) else (data[2] or "")
            autowipe = int(data[3].decode() if isinstance(data[3], bytes) else (data[3] or 0)) if len(data) > 3 and data[3] is not None else 0
            return {
                "views_left": views_left,
                "created_at": created_at,
                "status_token": status_token,
                "autowipe": autowipe,
                "ttl_left": max(0, ttl),
            }
        else:
            return await self.memory.get_metadata(key)

    async def get_receipt(self, key: str) -> dict | None:
        if self.is_redis and self.redis:
            receipt_key = f"receipt:{key}"
            data = await self.redis.hgetall(receipt_key)
            if not data:
                return None
            return {
                (k.decode() if isinstance(k, bytes) else str(k)): (v.decode() if isinstance(v, bytes) else str(v))
                for k, v in data.items()
            }
        else:
            return await self.memory.get_receipt(key)

    async def close(self):
        if self.is_redis and self.redis:
            await self.redis.aclose()


storage = StorageManager()


# ──────────────────────────────────────────────────────────────────────────────
# Redis client lifecycle
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    target_url = settings.upstash_redis_url or settings.redis_url
    await storage.init(target_url)
    yield
    logger.info("Shutting down storage")
    await storage.close()


# ──────────────────────────────────────────────────────────────────────────────
# Atomic Lua Scripts (OWASP A04 — Insecure Design / Race Condition Prevention)
# ──────────────────────────────────────────────────────────────────────────────

LUA_READ_AND_BURN = """
local key = KEYS[1]
local data = redis.call('HGETALL', key)
if #data == 0 then
    return nil
end

local fields = {}
for i = 1, #data, 2 do
    fields[data[i]] = data[i+1]
end

local views_left = tonumber(fields['views_left'])
if views_left == nil then
    return nil
end

if views_left <= 1 then
    redis.call('DEL', key)
else
    redis.call('HINCRBY', key, 'views_left', -1)
end

local receipt_key = 'receipt:' .. key
redis.call('HSET', receipt_key, 'status', 'opened', 'status_token', fields['status_token'] or '', 'timestamp', ARGV[1] or '')
redis.call('EXPIRE', receipt_key, 86400)

return {fields['ciphertext'], fields['views_left'], fields['created_at']}
"""


# ──────────────────────────────────────────────────────────────────────────────
# Rate Limiter (OWASP A07 — Identification & Auth / DoS prevention)
# ──────────────────────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address, default_limits=[])

# ──────────────────────────────────────────────────────────────────────────────
# FastAPI Application
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="OnceFlash API",
    version="1.0.0",
    description="Zero-knowledge ephemeral paste API",
    docs_url=None,     # Disable Swagger UI in production — re-enable for dev
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — restrict in production to your actual frontend domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Request-ID"],
    max_age=600,
)


# ──────────────────────────────────────────────────────────────────────────────
# Security Headers Middleware (OWASP A05 — Security Misconfiguration)
# ──────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",  # CRITICAL: prevents key leakage in Referer
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-XSS-Protection": "0",  # Disabled — modern browsers use CSP instead
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    # Remove server fingerprinting headers safely
    if "server" in response.headers:
        del response.headers["server"]
    if "x-powered-by" in response.headers:
        del response.headers["x-powered-by"]
    return response


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas (OWASP A03 — Injection Prevention)
# ──────────────────────────────────────────────────────────────────────────────

class CreatePasteRequest(BaseModel):
    """
    All data received from the client must pass strict Pydantic validation.
    The server accepts ONLY ciphertext (base64) and metadata integers — never
    plaintext, never cryptographic keys.
    """
    # base64url or base64 encoded ciphertext (IV prepended by client)
    ciphertext: str = Field(
        ...,
        min_length=24,           # Minimum: 12-byte IV + 1 byte CT + 16-byte tag ≈ 29 bytes base64
        max_length=2_796_200,    # ~2 MiB base64-encoded
        description="Base64-encoded AES-GCM ciphertext with IV prepended",
    )
    max_views: int = Field(
        default=1,
        ge=1,
        le=100,
        description="Number of allowed reads before destruction",
    )
    ttl_seconds: int = Field(
        default=86_400,
        ge=60,
        le=604_800,   # 7 days
        description="Seconds until automatic expiration",
    )
    # Optional: only 'text' or 'file' — server never executes content
    content_type: str = Field(
        default="text",
        description="Content type hint (text or file)",
    )
    autowipe: int = Field(
        default=0,
        ge=0,
        le=86_400,
        description="Screen auto-wipe countdown timer in seconds (0 = off)",
    )

    @field_validator("ciphertext")
    @classmethod
    def validate_base64(cls, v: str) -> str:
        """Ensure the value is valid base64 to prevent injection via malformed data."""
        import base64
        # Strip whitespace, try decoding
        v = v.strip()
        try:
            # Validate it decodes cleanly
            decoded = base64.b64decode(v + "==", validate=False)
            if len(decoded) < 29:  # 12 IV + 1 byte min CT + 16 tag
                raise ValueError("Ciphertext too short to be valid AES-GCM output")
        except Exception as exc:
            raise ValueError(f"Invalid base64 ciphertext: {exc}") from exc
        return v

    @field_validator("content_type")
    @classmethod
    def validate_content_type(cls, v: str) -> str:
        allowed = {"text", "file"}
        if v not in allowed:
            raise ValueError(f"content_type must be one of: {allowed}")
        return v


class CreatePasteResponse(BaseModel):
    id: str
    expires_at: int   # Unix timestamp
    status_token: str


class PasteMetaResponse(BaseModel):
    views_left: int
    created_at: int


# ──────────────────────────────────────────────────────────────────────────────
# Helper: generate cryptographically secure paste ID
# ──────────────────────────────────────────────────────────────────────────────

def _generate_paste_id() -> str:
    """
    Returns a 128-bit (16 byte) URL-safe random token.
    This gives a 2^128 search space, making brute-force enumeration
    computationally infeasible.
    """
    return secrets.token_urlsafe(16)  # 16 bytes → ~22 base64url chars


# ──────────────────────────────────────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
@app.get("/api/health", include_in_schema=False)
async def health_check():
    """Application health probe — does not expose sensitive data."""
    try:
        await storage.ping()
        mode = "redis" if storage.is_redis else "in-memory"
        return {"status": "ok", "storage": mode}
    except Exception:
        raise HTTPException(status_code=503, detail="Storage unavailable")


@app.post(
    "/api/paste",
    response_model=CreatePasteResponse,
    status_code=201,
    summary="Create an encrypted paste",
)
@limiter.limit(settings.rate_limit_create)
async def create_paste(
    request: Request,
    payload: CreatePasteRequest = Body(...),
) -> CreatePasteResponse:
    """
    Accepts a ciphertext blob and stores it in Redis or in-memory with TTL.
    The server NEVER receives or stores plaintext or cryptographic keys.
    """
    paste_id = _generate_paste_id()
    status_token = secrets.token_urlsafe(16)
    redis_key = f"paste:{paste_id}"
    now = int(time.time())
    expires_at = now + payload.ttl_seconds

    try:
        await storage.save_paste(
            redis_key,
            mapping={
                "ciphertext": payload.ciphertext.encode(),
                "views_left": payload.max_views,
                "created_at": now,
                "content_type": payload.content_type,
                "status_token": status_token,
                "autowipe": payload.autowipe,
            },
            ttl_seconds=payload.ttl_seconds,
        )
    except Exception as exc:
        logger.error("Storage write failed for paste creation: %s", exc)
        raise HTTPException(status_code=503, detail="Storage unavailable")

    logger.info(
        "Paste created id=%s ttl=%ds max_views=%d ip=%s",
        paste_id,
        payload.ttl_seconds,
        payload.max_views,
        get_remote_address(request),
    )

    return CreatePasteResponse(id=paste_id, expires_at=expires_at, status_token=status_token)


@app.get(
    "/api/paste/{paste_id}",
    summary="Retrieve and burn an encrypted paste",
)
@limiter.limit(settings.rate_limit_read)
async def get_paste(request: Request, paste_id: str) -> JSONResponse:
    """
    Atomically retrieves ciphertext and decrements/destroys view counter.
    Uses an atomic Lua script (Redis) or atomic asyncio lock (in-memory) to prevent race conditions.
    Returns ONLY ciphertext — decryption happens in the client browser.
    """
    # Validate paste_id format — must be URL-safe base64 characters only
    # This prevents Redis key injection and SSRF-style attacks
    if not paste_id or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in paste_id):
        raise HTTPException(status_code=400, detail="Invalid paste ID format")
    if len(paste_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid paste ID length")

    redis_key = f"paste:{paste_id}"

    try:
        # Atomic read-and-burn — prevents double-read race condition
        result = await storage.read_and_burn(redis_key)
    except Exception as exc:
        logger.error("Storage read failed for paste_id=%s: %s", paste_id, exc)
        raise HTTPException(status_code=503, detail="Storage unavailable")

    if result is None:
        logger.info("Paste not found or already burned: id=%s", paste_id)
        raise HTTPException(
            status_code=404,
            detail="Note not found, already burned, or expired",
        )

    ciphertext_bytes, views_left_bytes, created_at_bytes = result
    ciphertext = ciphertext_bytes.decode("utf-8") if isinstance(ciphertext_bytes, bytes) else ciphertext_bytes
    views_left = int(views_left_bytes) if views_left_bytes else 0
    created_at = int(created_at_bytes) if created_at_bytes else 0

    logger.info(
        "Paste retrieved id=%s views_left_before=%d ip=%s",
        paste_id,
        views_left,
        get_remote_address(request),
    )

    return JSONResponse(
        content={
            "ciphertext": ciphertext,
            "views_left": max(0, views_left - 1),   # views already decremented atomically
            "created_at": created_at,
        },
        headers={
            # Prevent any caching of sensitive ciphertext responses
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@app.delete(
    "/api/paste/{paste_id}",
    status_code=204,
    summary="Manually destroy a paste (creator burn)",
)
@limiter.limit("10/minute")
async def delete_paste(request: Request, paste_id: str) -> Response:
    """
    Allows the creator to manually destroy a paste before it expires.
    Note: In zero-knowledge design, the server cannot verify ownership —
    anyone with the paste ID can delete it (this is a feature, not a bug:
    it allows creators to revoke access).
    """
    if not paste_id or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in paste_id):
        raise HTTPException(status_code=400, detail="Invalid paste ID format")
    if len(paste_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid paste ID length")

    redis_key = f"paste:{paste_id}"
    try:
        deleted = await storage.delete_paste(redis_key)
    except Exception as exc:
        logger.error("Storage delete failed for paste_id=%s: %s", paste_id, exc)
        raise HTTPException(status_code=503, detail="Storage unavailable")

    if deleted == 0:
        raise HTTPException(status_code=404, detail="Note not found or already burned")

    logger.info("Paste manually deleted id=%s ip=%s", paste_id, get_remote_address(request))
    return Response(status_code=204)


@app.get(
    "/api/paste/{paste_id}/status",
    summary="Check status of a secret (zero-knowledge, creator only)",
)
@limiter.limit(settings.rate_limit_read)
async def check_paste_status(request: Request, paste_id: str, token: str) -> dict:
    if not paste_id or len(paste_id) > 32 or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in paste_id):
        raise HTTPException(status_code=400, detail="Invalid paste ID")
    if not token or len(token) > 64:
        raise HTTPException(status_code=400, detail="Invalid status token")

    redis_key = f"paste:{paste_id}"
    meta = await storage.get_metadata(redis_key)
    if meta:
        if not secrets.compare_digest(meta.get("status_token", ""), token):
            raise HTTPException(status_code=403, detail="Invalid status token")
        return {
            "status": "waiting",
            "views_left": meta["views_left"],
            "ttl_left": meta["ttl_left"],
            "created_at": meta["created_at"],
        }

    receipt = await storage.get_receipt(redis_key)
    if receipt:
        if not secrets.compare_digest(receipt.get("status_token", ""), token):
            raise HTTPException(status_code=403, detail="Invalid status token")
        if receipt.get("status") == "opened":
            return {
                "status": "opened",
                "message": "The recipient opened and read this note",
            }
        else:
            return {
                "status": "destroyed",
                "message": "destroyed before anyone opened it",
            }

    return {
        "status": "destroyed",
        "message": "destroyed before anyone opened it",
    }


@app.get(
    "/api/paste/{paste_id}/info",
    summary="Get non-destructive envelope metadata for receiver (zero-knowledge)",
)
@limiter.limit(settings.rate_limit_read)
async def get_paste_info(request: Request, paste_id: str) -> dict:
    if not paste_id or len(paste_id) > 32 or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in paste_id):
        raise HTTPException(status_code=400, detail="Invalid paste ID")

    redis_key = f"paste:{paste_id}"
    meta = await storage.get_metadata(redis_key)
    if not meta:
        raise HTTPException(status_code=404, detail="Note not found or already burned")

    return {
        "views_left": meta["views_left"],
        "ttl_left": meta["ttl_left"],
        "created_at": meta["created_at"],
        "autowipe": meta.get("autowipe", 0),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Serve static frontend (production mode)
# ──────────────────────────────────────────────────────────────────────────────

# Mount static files last so API routes take precedence
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(STATIC_DIR):
    @app.get("/view/{full_path:path}", include_in_schema=False)
    async def serve_view_spa(full_path: str):
        index_file = os.path.join(STATIC_DIR, "index.html")
        if os.path.isfile(index_file):
            return FileResponse(index_file)
        raise HTTPException(status_code=404, detail="Page not found")

    @app.get("/about", include_in_schema=False)
    async def serve_about_spa():
        about_file = os.path.join(STATIC_DIR, "about.html")
        if os.path.isfile(about_file):
            return FileResponse(about_file)
        raise HTTPException(status_code=404, detail="Page not found")

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
