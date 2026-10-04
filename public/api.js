/**
 * OnceFlash — API Client
 * Communicates with the FastAPI backend.
 * Never includes encryption keys in any request — they stay in the URL hash.
 */

"use strict";

const API_BASE = "/api";

/**
 * Create a new encrypted paste.
 * @param {string} ciphertext  Base64-encoded AES-GCM ciphertext
 * @param {object} opts
 * @param {number} opts.maxViews     1–100
 * @param {number} opts.ttlSeconds   60–604800
 * @param {string} opts.contentType  'text' or 'file'
 * @returns {Promise<{ id: string, expires_at: number }>}
 */
export async function createPaste(ciphertext, { maxViews = 1, ttlSeconds = 86400, contentType = "text", autowipe = 0 } = {}) {
  const response = await fetch(`${API_BASE}/paste`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ciphertext,
      max_views: maxViews,
      ttl_seconds: ttlSeconds,
      content_type: contentType,
      autowipe,
    }),
    // Credentials omitted — no session cookies needed for zero-knowledge model
    credentials: "omit",
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Unknown error" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Retrieve an encrypted paste (triggers burn-on-read on the server).
 * Only the paste ID is sent — the key stays in the browser.
 * @param {string} pasteId
 * @returns {Promise<{ ciphertext: string, views_left: number, created_at: number }>}
 */
export async function fetchPaste(pasteId) {
  const response = await fetch(`${API_BASE}/paste/${encodeURIComponent(pasteId)}`, {
    method: "GET",
    credentials: "omit",
    headers: { "Accept": "application/json" },
    // Prevent any caching of the ciphertext response
    cache: "no-store",
  });

  if (response.status === 404) {
    throw new Error("Note not found — it may have been burned or expired.");
  }
  if (response.status === 429) {
    throw new Error("Too many requests. Please wait before trying again.");
  }
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Unknown error" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Manually destroy a paste (creator revocation).
 * @param {string} pasteId
 * @returns {Promise<void>}
 */
export async function deletePaste(pasteId) {
  const response = await fetch(`${API_BASE}/paste/${encodeURIComponent(pasteId)}`, {
    method: "DELETE",
    credentials: "omit",
  });

  if (response.status === 204) return;
  if (response.status === 404) {
    throw new Error("Note not found or already burned.");
  }
  const err = await response.json().catch(() => ({ detail: "Unknown error" }));
  throw new Error(err.detail || `HTTP ${response.status}`);
}

/**
 * Check anonymous status of a paste using creator status token.
 * Never retrieves or returns ciphertext.
 * @param {string} pasteId
 * @param {string} token
 * @returns {Promise<{ status: string, views_left?: number, ttl_left?: number, created_at?: number, message?: string }>}
 */
export async function checkPasteStatus(pasteId, token) {
  const url = `${API_BASE}/paste/${encodeURIComponent(pasteId)}/status?token=${encodeURIComponent(token)}`;
  const response = await fetch(url, {
    method: "GET",
    credentials: "omit",
    cache: "no-store",
    headers: { "Accept": "application/json" },
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Failed to check status" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Retrieve non-destructive envelope metadata before revealing (zero-knowledge).
 * @param {string} pasteId
 * @returns {Promise<{ views_left: number, ttl_left: number, created_at: number }>}
 */
export async function fetchPasteInfo(pasteId) {
  const url = `${API_BASE}/paste/${encodeURIComponent(pasteId)}/info`;
  const response = await fetch(url, {
    method: "GET",
    credentials: "omit",
    cache: "no-store",
    headers: { "Accept": "application/json" },
  });

  if (response.status === 404) {
    throw new Error("Note not found — it may have been burned or expired.");
  }
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Failed to retrieve note details" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// Ephemeral Flash Room API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create a new zero-knowledge ephemeral flash room.
 * @param {object} opts
 * @param {number} opts.durationSeconds 300..1200 (5m..20m)
 * @param {number} opts.maxMembers 2..4
 * @returns {Promise<{ room_id: string, admin_token: string, expires_at: number, duration_seconds: number, max_members: number }>}
 */
export async function createRoom({ durationSeconds = 900, maxMembers = 4, clientId = null } = {}) {
  const payload = {
    duration_seconds: durationSeconds,
    max_members: maxMembers,
  };
  if (clientId) {
    payload.client_id = clientId;
  }
  const response = await fetch(`${API_BASE}/room`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    credentials: "omit",
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Failed to create room" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Host activates the room and starts the countdown timer.
 * @param {string} roomId
 * @param {string} adminToken
 * @returns {Promise<{ status: string, expires_at: number, duration_seconds: number, ttl_left: number }>}
 */
export async function startRoom(roomId, adminToken) {
  const response = await fetch(`${API_BASE}/room/${encodeURIComponent(roomId)}/start`, {
    method: "POST",
    headers: {
      "X-Admin-Token": adminToken,
      "Content-Type": "application/json",
    },
    credentials: "omit",
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Failed to start room" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Get room public metadata.
 * @param {string} roomId
 * @returns {Promise<{ expires_at: number, ttl_left: number, max_members: number, created_at: number, active_members: number }>}
 */
export async function fetchRoomInfo(roomId) {
  const response = await fetch(`${API_BASE}/room/${encodeURIComponent(roomId)}/info`, {
    method: "GET",
    credentials: "omit",
    cache: "no-store",
    headers: { "Accept": "application/json" },
  });

  if (response.status === 404) {
    throw new Error("Room not found or session ended");
  }
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Failed to fetch room info" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Join an ephemeral room.
 * @param {string} roomId
 * @param {string} clientId
 * @returns {Promise<{ status: string, expires_at: number, ttl_left: number, max_members: number, active_members: number }>}
 */
export async function joinRoom(roomId, clientId) {
  const response = await fetch(`${API_BASE}/room/${encodeURIComponent(roomId)}/join`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: clientId }),
    credentials: "omit",
  });

  if (response.status === 404) {
    throw new Error("Room not found or session ended");
  }
  if (response.status === 403) {
    throw new Error("Room is full");
  }
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Failed to join room" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Send an encrypted message to the room.
 * @param {string} roomId
 * @param {object} opts
 * @param {string} opts.clientId
 * @param {string} opts.sender
 * @param {string} opts.ciphertext
 * @param {string} opts.iv
 * @returns {Promise<{ status: string, timestamp: number }>}
 */
export async function sendRoomMessage(roomId, { clientId, sender, ciphertext, iv }) {
  const response = await fetch(`${API_BASE}/room/${encodeURIComponent(roomId)}/msg`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      sender,
      ciphertext,
      iv,
    }),
    credentials: "omit",
  });

  if (response.status === 404) {
    throw new Error("Room not found or session ended");
  }
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Failed to send message" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Poll messages from the room.
 * @param {string} roomId
 * @param {object} opts
 * @param {string} opts.clientId
 * @param {number} opts.since
 * @returns {Promise<{ messages: Array, total: number, expires_at: number, ttl_left: number, max_members: number, active_members: number }>}
 */
export async function fetchRoomMessages(roomId, { clientId, since = 0 }) {
  const url = `${API_BASE}/room/${encodeURIComponent(roomId)}/msgs?client_id=${encodeURIComponent(clientId)}&since=${encodeURIComponent(since)}`;
  const response = await fetch(url, {
    method: "GET",
    credentials: "omit",
    cache: "no-store",
    headers: { "Accept": "application/json" },
  });

  if (response.status === 404) {
    throw new Error("Room not found or session ended");
  }
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: "Failed to fetch messages" }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

/**
 * Destroy a room permanently (host only).
 * @param {string} roomId
 * @param {string} adminToken
 * @returns {Promise<void>}
 */
export async function destroyRoom(roomId, adminToken) {
  const response = await fetch(`${API_BASE}/room/${encodeURIComponent(roomId)}`, {
    method: "DELETE",
    headers: {
      "X-Admin-Token": adminToken,
    },
    credentials: "omit",
  });

  if (response.status === 204) return;
  if (response.status === 404) {
    throw new Error("Room not found or already destroyed");
  }
  const err = await response.json().catch(() => ({ detail: "Failed to destroy room" }));
  throw new Error(err.detail || `HTTP ${response.status}`);
}


