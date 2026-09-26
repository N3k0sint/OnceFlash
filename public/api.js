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
export async function createPaste(ciphertext, { maxViews = 1, ttlSeconds = 86400, contentType = "text" } = {}) {
  const response = await fetch(`${API_BASE}/paste`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ciphertext,
      max_views: maxViews,
      ttl_seconds: ttlSeconds,
      content_type: contentType,
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
