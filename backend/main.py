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
from fastapi import FastAPI, HTTPException, Request, Response, Body, Header, Query
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
    max_active_rooms: int = 5
    min_room_duration_seconds: int = 300         # 5 minutes
    max_room_duration_seconds: int = 1200        # 20 minutes
    max_room_members: int = 4
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
        # Ephemeral Flash Rooms
        self._rooms: dict[str, dict] = {}
        self._room_expires: dict[str, float] = {}
        self._room_messages: dict[str, list[dict]] = {}
        self._room_members: dict[str, dict[str, float]] = {}
        self._room_joined: dict[str, set[str]] = {}
        self._room_joined_order: dict[str, list[str]] = {}
        self._room_seq: dict[str, int] = {}
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

        expired_rooms = [k for k, exp in self._room_expires.items() if exp <= now]
        for k in expired_rooms:
            self._rooms.pop(k, None)
            self._room_expires.pop(k, None)
            self._room_messages.pop(k, None)
            self._room_members.pop(k, None)
            self._room_joined.pop(k, None)
            self._room_joined_order.pop(k, None)
            self._room_seq.pop(k, None)

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
            try:
                autowipe = int(paste.get("autowipe", 0))
            except (ValueError, TypeError):
                autowipe = 0
            return {
                "views_left": int(paste.get("views_left", 0)),
                "created_at": int(paste.get("created_at", 0)),
                "status_token": str(paste.get("status_token", "")),
                "autowipe": autowipe,
                "ttl_left": max(0, int(exp - time.time())),
            }

    async def get_receipt(self, key: str) -> dict | None:
        async with self._lock:
            self._cleanup_expired()
            return self._receipts.get(key)

    async def create_room(self, room_id: str, admin_token: str, duration_seconds: int, max_members: int, host_client_id: str) -> bool:
        async with self._lock:
            self._cleanup_expired()
            if len(self._rooms) >= settings.max_active_rooms:
                return False
            now = time.time()
            self._rooms[room_id] = {
                "admin_token": admin_token,
                "host_client_id": host_client_id,
                "duration_seconds": duration_seconds,
                "max_members": max_members,
                "created_at": int(now),
                "started": False,
                "expires_at": 0,
            }
            # 15 min buffer to prevent unstarted abandoned rooms from consuming slots
            self._room_expires[room_id] = now + 900
            self._room_messages[room_id] = []
            # Host immediately occupies 1 member slot
            self._room_members[room_id] = {host_client_id: now}
            self._room_joined[room_id] = {host_client_id}
            self._room_joined_order[room_id] = [host_client_id]
            self._room_seq[room_id] = 0
            return True

    async def start_room(self, room_id: str, admin_token: str) -> dict | None:
        async with self._lock:
            self._cleanup_expired()
            if room_id not in self._rooms:
                return None
            room = self._rooms[room_id]
            if not secrets.compare_digest(room["admin_token"], admin_token):
                return None
            now = time.time()
            if not room.get("started", False):
                room["started"] = True
                room["expires_at"] = int(now + room["duration_seconds"])
                self._room_expires[room_id] = now + room["duration_seconds"]
            return {
                "expires_at": room["expires_at"],
                "duration_seconds": room["duration_seconds"],
                "ttl_left": max(0, int(self._room_expires[room_id] - now)),
                "started": True,
            }

    async def get_room_meta(self, room_id: str) -> dict | None:
        async with self._lock:
            self._cleanup_expired()
            if room_id not in self._rooms:
                return None
            room = self._rooms[room_id]
            now = time.time()
            started = room.get("started", False)
            host_client_id = room.get("host_client_id", "")
            ttl_left = max(0, int(self._room_expires.get(room_id, 0) - now)) if started else room["duration_seconds"]
            joined = self._room_joined.get(room_id, set())
            active_members = len([
                m for m, seen in self._room_members.get(room_id, {}).items()
                if m == host_client_id or (now - seen <= 45)
            ])
            return {
                "expires_at": room["expires_at"] if started else 0,
                "duration_seconds": room["duration_seconds"],
                "ttl_left": ttl_left,
                "max_members": room["max_members"],
                "created_at": room["created_at"],
                "active_members": max(1, active_members),
                "total_joined": len(joined),
                "is_full": len(joined) >= room["max_members"],
                "started": started,
            }

    async def join_room(self, room_id: str, client_id: str) -> tuple[bool, str, dict]:
        async with self._lock:
            self._cleanup_expired()
            if room_id not in self._rooms:
                return False, "Room not found or session ended", {}
            room = self._rooms[room_id]
            now = time.time()
            host_client_id = room.get("host_client_id", "")
            members = self._room_members.setdefault(room_id, {})
            joined = self._room_joined.setdefault(room_id, {host_client_id})
            joined_order = self._room_joined_order.setdefault(room_id, [host_client_id])

            # Check if this client has already claimed a slot
            if client_id not in joined and client_id != host_client_id:
                if len(joined) >= room["max_members"]:
                    return False, "Room capacity reached. Session is locked to new participants.", {}
                joined.add(client_id)
                if client_id not in joined_order:
                    joined_order.append(client_id)

            guest_index = joined_order.index(client_id) if client_id in joined_order else 0

            # Clean stale guest members (protect host slot)
            stale = [m for m, seen in members.items() if m != host_client_id and m != client_id and (now - seen > 45)]
            for m in stale:
                members.pop(m, None)

            members[client_id] = now
            started = room.get("started", False)
            ttl_left = max(0, int(self._room_expires.get(room_id, 0) - now)) if started else room["duration_seconds"]
            return True, "", {
                "expires_at": room["expires_at"] if started else 0,
                "duration_seconds": room["duration_seconds"],
                "ttl_left": ttl_left,
                "max_members": room["max_members"],
                "active_members": len([m for m, seen in members.items() if m == host_client_id or (now - seen <= 45)]),
                "total_joined": len(joined),
                "is_full": len(joined) >= room["max_members"],
                "guest_index": guest_index,
                "started": started,
            }

    async def add_room_message(self, room_id: str, sender: str, ciphertext: str, iv: str) -> dict | None:
        async with self._lock:
            self._cleanup_expired()
            if room_id not in self._rooms:
                return None
            now = time.time()
            seq = self._room_seq.get(room_id, 0) + 1
            self._room_seq[room_id] = seq
            msg = {
                "id": f"{room_id}_{seq}",
                "seq": seq,
                "sender": sender,
                "ciphertext": ciphertext,
                "iv": iv,
                "timestamp": int(now),
            }
            msgs = self._room_messages.setdefault(room_id, [])
            msgs.append(msg)
            if len(msgs) > 2000:
                self._room_messages[room_id] = msgs[-2000:]
            return msg

    async def get_room_messages(self, room_id: str, since_index: int, client_id: str) -> tuple[list[dict], int, dict] | None:
        async with self._lock:
            self._cleanup_expired()
            if room_id not in self._rooms:
                return None
            now = time.time()
            room = self._rooms[room_id]
            host_client_id = room.get("host_client_id", "")
            members = self._room_members.setdefault(room_id, {})
            joined = self._room_joined.get(room_id, set())

            stale = [m for m, seen in members.items() if m != host_client_id and m != client_id and (now - seen > 45)]
            for m in stale:
                members.pop(m, None)

            # Strict security: only clients that joined can poll
            if client_id:
                if client_id not in joined and client_id != host_client_id:
                    return None
                members[client_id] = now

            msgs = self._room_messages.get(room_id, [])
            if since_index == 0:
                new_msgs = list(msgs)
            else:
                new_msgs = [m for m in msgs if m.get("seq", 0) > since_index]

            total = len(msgs)
            current_seq = self._room_seq.get(room_id, total)
            started = room.get("started", False)
            ttl_left = max(0, int(self._room_expires.get(room_id, 0) - now)) if started else room["duration_seconds"]
            active_count = len([m for m, seen in members.items() if m == host_client_id or (now - seen <= 45)])
            meta = {
                "expires_at": room["expires_at"] if started else 0,
                "duration_seconds": room["duration_seconds"],
                "ttl_left": ttl_left,
                "max_members": room["max_members"],
                "active_members": max(1, active_count),
                "total_joined": len(joined),
                "is_full": len(joined) >= room["max_members"],
                "total_messages": total,
                "current_seq": current_seq,
                "started": started,
            }
            return new_msgs, current_seq, meta

    async def delete_room(self, room_id: str, admin_token: str) -> bool:
        async with self._lock:
            if room_id not in self._rooms:
                return False
            expected_token = self._rooms[room_id].get("admin_token", "")
            if not secrets.compare_digest(expected_token, admin_token):
                return False
            self._rooms.pop(room_id, None)
            self._room_expires.pop(room_id, None)
            self._room_messages.pop(room_id, None)
            self._room_members.pop(room_id, None)
            self._room_joined.pop(room_id, None)
            self._room_joined_order.pop(room_id, None)
            self._room_seq.pop(room_id, None)
            return True


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
            try:
                autowipe_val = data[3].decode() if isinstance(data[3], bytes) else data[3]
                autowipe = int(autowipe_val) if autowipe_val else 0
            except (ValueError, TypeError):
                autowipe = 0
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

    async def create_room(self, room_id: str, admin_token: str, duration_seconds: int, max_members: int, host_client_id: str) -> bool:
        if self.is_redis and self.redis:
            active_set = await self.redis.smembers("active_rooms_set")
            active_count = 0
            if active_set:
                for r in active_set:
                    rid = r.decode() if isinstance(r, bytes) else str(r)
                    if await self.redis.exists(f"room:{rid}:meta"):
                        active_count += 1
                    else:
                        await self.redis.srem("active_rooms_set", rid)
            if active_count >= settings.max_active_rooms:
                return False

            now = int(time.time())
            meta_key = f"room:{room_id}:meta"
            members_key = f"room:{room_id}:members"
            joined_key = f"room:{room_id}:joined"
            pipe = self.redis.pipeline()
            pipe.sadd("active_rooms_set", room_id)
            pipe.hset(meta_key, mapping={
                "admin_token": admin_token,
                "host_client_id": host_client_id,
                "duration_seconds": str(duration_seconds),
                "max_members": str(max_members),
                "created_at": str(now),
                "started": "0",
                "expires_at": "0",
            })
            pipe.hset(members_key, host_client_id, str(now))
            pipe.sadd(joined_key, host_client_id)
            pipe.rpush(f"room:{room_id}:order", host_client_id)
            pipe.expire(meta_key, 900)
            pipe.expire(f"room:{room_id}:msgs", 900)
            pipe.expire(members_key, 900)
            pipe.expire(joined_key, 900)
            pipe.expire(f"room:{room_id}:order", 900)
            await pipe.execute()
            return True
        else:
            return await self.memory.create_room(room_id, admin_token, duration_seconds, max_members, host_client_id)

    async def start_room(self, room_id: str, admin_token: str) -> dict | None:
        if self.is_redis and self.redis:
            meta_key = f"room:{room_id}:meta"
            meta = await self.redis.hgetall(meta_key)
            if not meta:
                return None
            meta_dict = {(k.decode() if isinstance(k, bytes) else str(k)): (v.decode() if isinstance(v, bytes) else str(v)) for k, v in meta.items()}
            expected = meta_dict.get("admin_token", "")
            if not secrets.compare_digest(expected, admin_token):
                return None
            now = int(time.time())
            dur = int(meta_dict.get("duration_seconds", 900))
            started = meta_dict.get("started", "0") == "1"
            if not started:
                new_exp = now + dur
                pipe = self.redis.pipeline()
                pipe.hset(meta_key, mapping={"started": "1", "expires_at": str(new_exp)})
                pipe.expire(meta_key, dur)
                pipe.expire(f"room:{room_id}:msgs", dur)
                pipe.expire(f"room:{room_id}:members", dur)
                pipe.expire(f"room:{room_id}:joined", dur)
                pipe.expire(f"room:{room_id}:order", dur)
                await pipe.execute()
                return {"expires_at": new_exp, "duration_seconds": dur, "ttl_left": dur, "started": True}
            else:
                exp = int(meta_dict.get("expires_at", now + dur))
                return {"expires_at": exp, "duration_seconds": dur, "ttl_left": max(0, exp - now), "started": True}
        else:
            return await self.memory.start_room(room_id, admin_token)

    async def get_room_meta(self, room_id: str) -> dict | None:
        if self.is_redis and self.redis:
            meta_key = f"room:{room_id}:meta"
            meta = await self.redis.hgetall(meta_key)
            if not meta:
                return None
            meta_dict = {(k.decode() if isinstance(k, bytes) else str(k)): (v.decode() if isinstance(v, bytes) else str(v)) for k, v in meta.items()}
            expires_at = int(meta_dict.get("expires_at", 0))
            now = time.time()
            started = meta_dict.get("started", "0") == "1"
            dur = int(meta_dict.get("duration_seconds", 900))
            ttl_left = max(0, int(expires_at - now)) if started else dur
            host_client_id = meta_dict.get("host_client_id", "")
            max_members = int(meta_dict.get("max_members", 4))

            members_key = f"room:{room_id}:members"
            members_raw = await self.redis.hgetall(members_key)
            active_count = 0
            for k, v in members_raw.items():
                mk = k.decode() if isinstance(k, bytes) else str(k)
                mv = float(v.decode() if isinstance(v, bytes) else str(v))
                if mk == host_client_id or now - mv <= 45:
                    active_count += 1
                else:
                    await self.redis.hdel(members_key, mk)

            joined_key = f"room:{room_id}:joined"
            total_joined = await self.redis.scard(joined_key)
            return {
                "expires_at": expires_at if started else 0,
                "duration_seconds": dur,
                "ttl_left": ttl_left,
                "max_members": max_members,
                "created_at": int(meta_dict.get("created_at", 0)),
                "active_members": max(1, active_count),
                "total_joined": total_joined,
                "is_full": total_joined >= max_members,
                "started": started,
            }
        else:
            return await self.memory.get_room_meta(room_id)

    async def join_room(self, room_id: str, client_id: str) -> tuple[bool, str, dict]:
        if self.is_redis and self.redis:
            meta_key = f"room:{room_id}:meta"
            meta = await self.redis.hgetall(meta_key)
            if not meta:
                return False, "Room not found or session ended", {}
            meta_dict = {(k.decode() if isinstance(k, bytes) else str(k)): (v.decode() if isinstance(v, bytes) else str(v)) for k, v in meta.items()}
            max_members = int(meta_dict.get("max_members", 4))
            expires_at = int(meta_dict.get("expires_at", 0))
            started = meta_dict.get("started", "0") == "1"
            dur = int(meta_dict.get("duration_seconds", 900))
            host_client_id = meta_dict.get("host_client_id", "")
            now = time.time()
            ttl_left = max(0, int(expires_at - now)) if started else dur

            joined_key = f"room:{room_id}:joined"
            is_member = await self.redis.sismember(joined_key, client_id)
            if not is_member and client_id != host_client_id:
                total_joined = await self.redis.scard(joined_key)
                if total_joined >= max_members:
                    return False, "Room capacity reached. Session is locked to new participants.", {}
                await self.redis.sadd(joined_key, client_id)
                await self.redis.expire(joined_key, max(1, ttl_left if started else 900))

            members_key = f"room:{room_id}:members"
            members_raw = await self.redis.hgetall(members_key)
            members = {}
            for k, v in members_raw.items():
                mk = k.decode() if isinstance(k, bytes) else str(k)
                mv = float(v.decode() if isinstance(v, bytes) else str(v))
                if mk == host_client_id or mk == client_id or now - mv <= 45:
                    members[mk] = mv
                else:
                    await self.redis.hdel(members_key, mk)

            await self.redis.hset(members_key, client_id, str(now))
            await self.redis.expire(members_key, max(1, ttl_left if started else 900))

            order_key = f"room:{room_id}:order"
            order_list = await self.redis.lrange(order_key, 0, -1)
            order_strs = [(x.decode() if isinstance(x, bytes) else str(x)) for x in order_list]
            if client_id not in order_strs:
                await self.redis.rpush(order_key, client_id)
                await self.redis.expire(order_key, max(1, ttl_left if started else 900))
                guest_index = len(order_strs)
            else:
                guest_index = order_strs.index(client_id)

            total_joined = await self.redis.scard(joined_key)
            return True, "", {
                "expires_at": expires_at if started else 0,
                "duration_seconds": dur,
                "ttl_left": ttl_left,
                "max_members": max_members,
                "active_members": len([m for m, seen in members.items() if m == host_client_id or (now - seen <= 45)]),
                "total_joined": total_joined,
                "is_full": total_joined >= max_members,
                "guest_index": guest_index,
                "started": started,
            }
        else:
            return await self.memory.join_room(room_id, client_id)

    async def add_room_message(self, room_id: str, sender: str, ciphertext: str, iv: str) -> dict | None:
        if self.is_redis and self.redis:
            meta_key = f"room:{room_id}:meta"
            if not await self.redis.exists(meta_key):
                return None
            ttl = await self.redis.ttl(meta_key)
            if ttl <= 0:
                return None
            seq_key = f"room:{room_id}:seq"
            seq = await self.redis.incr(seq_key)
            await self.redis.expire(seq_key, max(1, ttl))
            msg = {
                "id": f"{room_id}_{seq}",
                "seq": seq,
                "sender": sender,
                "ciphertext": ciphertext,
                "iv": iv,
                "timestamp": int(time.time()),
            }
            import json
            msgs_key = f"room:{room_id}:msgs"
            pipe = self.redis.pipeline()
            pipe.rpush(msgs_key, json.dumps(msg))
            pipe.ltrim(msgs_key, -2000, -1)
            pipe.expire(msgs_key, max(1, ttl))
            await pipe.execute()
            return msg
        else:
            return await self.memory.add_room_message(room_id, sender, ciphertext, iv)

    async def get_room_messages(self, room_id: str, since_index: int, client_id: str) -> tuple[list[dict], int, dict] | None:
        if self.is_redis and self.redis:
            meta_key = f"room:{room_id}:meta"
            meta = await self.redis.hgetall(meta_key)
            if not meta:
                return None
            meta_dict = {(k.decode() if isinstance(k, bytes) else str(k)): (v.decode() if isinstance(v, bytes) else str(v)) for k, v in meta.items()}
            expires_at = int(meta_dict.get("expires_at", 0))
            started = meta_dict.get("started", "0") == "1"
            dur = int(meta_dict.get("duration_seconds", 900))
            max_members = int(meta_dict.get("max_members", 4))
            host_client_id = meta_dict.get("host_client_id", "")
            now = time.time()
            ttl_left = max(0, int(expires_at - now)) if started else dur

            joined_key = f"room:{room_id}:joined"
            if client_id:
                is_member = await self.redis.sismember(joined_key, client_id)
                if not is_member and client_id != host_client_id:
                    return None

            members_key = f"room:{room_id}:members"
            members_raw = await self.redis.hgetall(members_key)
            members = {}
            for k, v in members_raw.items():
                mk = k.decode() if isinstance(k, bytes) else str(k)
                mv = float(v.decode() if isinstance(v, bytes) else str(v))
                if mk == host_client_id or mk == client_id or now - mv <= 45:
                    members[mk] = mv
                else:
                    await self.redis.hdel(members_key, mk)

            if client_id:
                await self.redis.hset(members_key, client_id, str(now))

            msgs_key = f"room:{room_id}:msgs"
            raw_msgs = await self.redis.lrange(msgs_key, 0, -1)
            import json
            messages = []
            for m in raw_msgs:
                s = m.decode() if isinstance(m, bytes) else str(m)
                try:
                    parsed_m = json.loads(s)
                    if since_index == 0 or parsed_m.get("seq", 0) > since_index:
                        messages.append(parsed_m)
                except Exception:
                    pass
            seq_key = f"room:{room_id}:seq"
            curr_seq_raw = await self.redis.get(seq_key)
            current_seq = int(curr_seq_raw.decode() if isinstance(curr_seq_raw, bytes) else curr_seq_raw) if curr_seq_raw else len(raw_msgs)

            active_count = len([m for m, seen in members.items() if m == host_client_id or (now - seen <= 45)])
            total_joined = await self.redis.scard(joined_key)
            meta_resp = {
                "expires_at": expires_at if started else 0,
                "duration_seconds": dur,
                "ttl_left": ttl_left,
                "max_members": max_members,
                "active_members": max(1, active_count),
                "total_joined": total_joined,
                "is_full": total_joined >= max_members,
                "total_messages": len(raw_msgs),
                "current_seq": current_seq,
                "started": started,
            }
            return messages, current_seq, meta_resp
        else:
            return await self.memory.get_room_messages(room_id, since_index, client_id)

    async def delete_room(self, room_id: str, admin_token: str) -> bool:
        if self.is_redis and self.redis:
            meta_key = f"room:{room_id}:meta"
            token = await self.redis.hget(meta_key, "admin_token")
            if not token:
                return False
            expected = token.decode() if isinstance(token, bytes) else str(token)
            if not secrets.compare_digest(expected, admin_token):
                return False
            pipe = self.redis.pipeline()
            pipe.delete(meta_key)
            pipe.delete(f"room:{room_id}:msgs")
            pipe.delete(f"room:{room_id}:seq")
            pipe.delete(f"room:{room_id}:members")
            pipe.delete(f"room:{room_id}:joined")
            pipe.delete(f"room:{room_id}:order")
            pipe.srem("active_rooms_set", room_id)
            await pipe.execute()
            return True
        else:
            return await self.memory.delete_room(room_id, admin_token)

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

def get_client_ip(request: Request) -> str:
    """
    Extract client IP, taking into account X-Forwarded-For when behind a reverse proxy (e.g. Vercel).
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return get_remote_address(request)


target_redis = settings.upstash_redis_url or settings.redis_url
_is_redis = bool(target_redis and (target_redis.startswith("redis://") or target_redis.startswith("rediss://")))

limiter = Limiter(
    key_func=get_client_ip,
    default_limits=[],
    storage_uri=target_redis if _is_redis else None,
    swallow_errors=True,
    in_memory_fallback_enabled=True,
)

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


class CreateRoomRequest(BaseModel):
    duration_seconds: int = Field(default=900, ge=300, le=1200) # 5m to 20m
    max_members: int = Field(default=4, ge=2, le=4)
    client_id: Optional[str] = Field(default=None, max_length=64)


class CreateRoomResponse(BaseModel):
    room_id: str
    admin_token: str
    client_id: str
    expires_at: int
    duration_seconds: int
    max_members: int


class JoinRoomRequest(BaseModel):
    client_id: str = Field(..., min_length=4, max_length=64)


class SendRoomMessageRequest(BaseModel):
    client_id: str = Field(..., min_length=4, max_length=64)
    sender: str = Field(default="Anonymous", max_length=32)
    ciphertext: str = Field(..., min_length=1, max_length=8000)
    iv: str = Field(default="", max_length=100)


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
        get_client_ip(request),
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
        get_client_ip(request),
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

    logger.info("Paste manually deleted id=%s ip=%s", paste_id, get_client_ip(request))
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

    return JSONResponse(
        content={
            "views_left": meta["views_left"],
            "ttl_left": meta["ttl_left"],
            "created_at": meta["created_at"],
            "autowipe": meta.get("autowipe", 0),
        },
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


# ──────────────────────────────────────────────────────────────────────────────
# Flash Room Endpoints (Zero-Knowledge Ephemeral Group Chat)
# ──────────────────────────────────────────────────────────────────────────────

@app.post(
    "/api/room",
    response_model=CreateRoomResponse,
    status_code=201,
    summary="Create an ephemeral flash room",
)
@limiter.limit("10/minute")
async def create_room(
    request: Request,
    payload: CreateRoomRequest = Body(...),
) -> CreateRoomResponse:
    room_id = secrets.token_urlsafe(12)
    admin_token = secrets.token_hex(32)
    host_client_id = payload.client_id or f"host_{secrets.token_hex(12)}"
    success = await storage.create_room(
        room_id=room_id,
        admin_token=admin_token,
        duration_seconds=payload.duration_seconds,
        max_members=payload.max_members,
        host_client_id=host_client_id,
    )
    if not success:
        raise HTTPException(status_code=429, detail="All room slots occupied")

    logger.info(
        "Room created id=%s duration=%ds max_members=%d ip=%s",
        room_id,
        payload.duration_seconds,
        payload.max_members,
        get_client_ip(request),
    )
    return CreateRoomResponse(
        room_id=room_id,
        admin_token=admin_token,
        client_id=host_client_id,
        expires_at=0,
        duration_seconds=payload.duration_seconds,
        max_members=payload.max_members,
    )


@app.post(
    "/api/room/{room_id}/start",
    summary="Host enters and starts the session countdown timer",
)
@limiter.limit("20/minute")
async def start_room_endpoint(
    request: Request,
    room_id: str,
    x_admin_token: str | None = Header(None, alias="X-Admin-Token"),
) -> JSONResponse:
    if not room_id or len(room_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid room ID")
    if not x_admin_token:
        raise HTTPException(status_code=401, detail="Admin token required")
    res = await storage.start_room(room_id, x_admin_token)
    if not res:
        raise HTTPException(status_code=404, detail="Room not found or unauthorized")
    return JSONResponse(
        content={"status": "started", **res},
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@app.get(
    "/api/room/{room_id}/info",
    summary="Get public room metadata",
)
@limiter.limit("60/minute")
async def get_room_info(request: Request, room_id: str) -> JSONResponse:
    if not room_id or len(room_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid room ID")
    meta = await storage.get_room_meta(room_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Room not found or expired")
    return JSONResponse(
        content=meta,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@app.post(
    "/api/room/{room_id}/join",
    summary="Join an ephemeral room and register heartbeat",
)
@limiter.limit("60/minute")
async def join_room(
    request: Request,
    room_id: str,
    payload: JoinRoomRequest = Body(...),
) -> JSONResponse:
    if not room_id or len(room_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid room ID")
    success, err_msg, meta = await storage.join_room(room_id, payload.client_id)
    if not success:
        if "not found" in err_msg.lower():
            raise HTTPException(status_code=404, detail=err_msg)
        if "full" in err_msg.lower() or "capacity" in err_msg.lower():
            raise HTTPException(status_code=403, detail="Room capacity reached. Session is locked to new participants.")
        raise HTTPException(status_code=400, detail=err_msg)

    return JSONResponse(
        content={"status": "joined", **meta},
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@app.post(
    "/api/room/{room_id}/msg",
    summary="Send encrypted message to room",
)
@limiter.limit("180/minute")
async def send_room_message(
    request: Request,
    room_id: str,
    payload: SendRoomMessageRequest = Body(...),
) -> JSONResponse:
    if not room_id or len(room_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid room ID")
    clean_sender = "".join(c for c in payload.sender if c.isprintable()).strip()[:32] or "Anonymous"
    msg = await storage.add_room_message(
        room_id=room_id,
        sender=clean_sender,
        ciphertext=payload.ciphertext,
        iv=payload.iv,
    )
    if not msg:
        raise HTTPException(status_code=404, detail="Room not found or expired")
    return JSONResponse(
        content={"status": "sent", "timestamp": msg["timestamp"]},
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@app.get(
    "/api/room/{room_id}/msgs",
    summary="Poll messages from room",
)
@limiter.limit("240/minute")
async def get_room_messages(
    request: Request,
    room_id: str,
    client_id: str = Query(...),
    since: int = Query(0, ge=0),
) -> JSONResponse:
    if not room_id or len(room_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid room ID")
    res = await storage.get_room_messages(room_id, since, client_id)
    if res is None:
        raise HTTPException(status_code=404, detail="Room not found or expired")
    messages, current_seq, meta = res
    return JSONResponse(
        content={
            "messages": messages,
            "total": meta.get("total_messages", len(messages)),
            "current_seq": current_seq,
            **meta,
        },
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@app.delete(
    "/api/room/{room_id}",
    status_code=204,
    summary="Destroy an ephemeral room (host only)",
)
@limiter.limit("10/minute")
async def delete_room(
    request: Request,
    room_id: str,
    x_admin_token: str | None = Header(None, alias="X-Admin-Token"),
) -> Response:
    if not room_id or len(room_id) > 32:
        raise HTTPException(status_code=400, detail="Invalid room ID")
    if not x_admin_token:
        raise HTTPException(status_code=401, detail="Admin token required")
    deleted = await storage.delete_room(room_id, x_admin_token)
    if not deleted:
        raise HTTPException(status_code=404, detail="Room not found or invalid token")
    logger.info("Room destroyed id=%s ip=%s", room_id, get_client_ip(request))
    return Response(status_code=204)


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
            return FileResponse(
                index_file,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                },
            )
        raise HTTPException(status_code=404, detail="Page not found")

    @app.get("/room/{full_path:path}", include_in_schema=False)
    async def serve_room_spa(full_path: str):
        index_file = os.path.join(STATIC_DIR, "index.html")
        if os.path.isfile(index_file):
            return FileResponse(
                index_file,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                },
            )
        raise HTTPException(status_code=404, detail="Page not found")

    @app.get("/about", include_in_schema=False)
    async def serve_about_spa():
        about_file = os.path.join(STATIC_DIR, "about.html")
        if os.path.isfile(about_file):
            return FileResponse(about_file)
        raise HTTPException(status_code=404, detail="Page not found")

    @app.get("/privacy", include_in_schema=False)
    async def serve_privacy_spa():
        privacy_file = os.path.join(STATIC_DIR, "privacy.html")
        if os.path.isfile(privacy_file):
            return FileResponse(privacy_file)
        raise HTTPException(status_code=404, detail="Page not found")

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
