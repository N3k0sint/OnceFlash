/**
 * OnceFlash — Web Crypto API Wrapper
 * 
 * All cryptographic operations run EXCLUSIVELY in the browser using the
 * Web Crypto API (window.crypto.subtle). The server NEVER receives keys.
 * 
 * Algorithm: AES-GCM 256-bit
 * IV:        96-bit (12 bytes), generated fresh per message via CSPRNG
 * Key:       256-bit, generated via CSPRNG, stored only in URL #fragment
 * 
 * Wire format: base64( IV[12 bytes] ∥ Ciphertext ∥ AuthTag[16 bytes] )
 * AuthTag is appended automatically by AES-GCM and validates integrity.
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// Crypto primitives
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a fresh 256-bit AES-GCM key using the browser's CSPRNG.
 * @returns {Promise<CryptoKey>} Exportable AES-GCM key
 */
export async function generateKey() {
  return window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,       // extractable — must be true to export to URL hash
    ["encrypt", "decrypt"]
  );
}

/**
 * Export a CryptoKey to a base64url string for embedding in the URL fragment.
 * The key MUST only ever be placed in the URL hash (#), never in the path,
 * query string, or HTTP headers.
 * @param {CryptoKey} key
 * @returns {Promise<string>} base64url-encoded raw key bytes
 */
export async function exportKey(key) {
  const raw = await window.crypto.subtle.exportKey("raw", key);
  return bufferToBase64url(raw);
}

/**
 * Import a base64url-encoded raw key string back into a CryptoKey.
 * @param {string} base64urlKey
 * @returns {Promise<CryptoKey>}
 */
export async function importKey(base64urlKey) {
  const raw = base64urlToBuffer(base64urlKey);
  return window.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM", length: 256 },
    false,      // not extractable on import — reduces key exposure window
    ["decrypt"]
  );
}

/**
 * Encrypt a plaintext string.
 * 
 * Steps:
 *   1. Encode plaintext as UTF-8 bytes
 *   2. Generate a fresh 96-bit IV via CSPRNG (never reuse IVs!)
 *   3. AES-GCM encrypt (appends 128-bit auth tag automatically)
 *   4. Prepend IV to ciphertext bytes
 *   5. Base64-encode the whole thing for JSON transport
 * 
 * @param {CryptoKey} key   AES-GCM key
 * @param {string} plaintext
 * @returns {Promise<string>} base64-encoded(IV ∥ ciphertext ∥ authtag)
 */
export async function encrypt(key, plaintext) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  // Fresh IV per message — CRITICAL security requirement.
  // Reusing an IV with the same key in AES-GCM completely breaks confidentiality.
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96 bits

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  // Concatenate IV ∥ ciphertext (auth tag already appended by AES-GCM)
  const combined = new Uint8Array(iv.byteLength + ciphertextBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertextBuffer), iv.byteLength);

  return bufferToBase64(combined);
}

/**
 * Decrypt a base64-encoded ciphertext blob.
 * 
 * Steps:
 *   1. Base64-decode the blob
 *   2. Extract IV (first 12 bytes)
 *   3. AES-GCM decrypt (verifies auth tag — throws on tampering)
 *   4. Decode UTF-8 bytes → plaintext string
 * 
 * @param {CryptoKey} key
 * @param {string} base64Ciphertext  base64-encoded(IV ∥ ciphertext ∥ authtag)
 * @returns {Promise<string>} plaintext
 * @throws {DOMException} if decryption fails (wrong key or tampered ciphertext)
 */
export async function decrypt(key, base64Ciphertext) {
  const combined = base64ToBuffer(base64Ciphertext);

  if (combined.byteLength < 12 + 16) {
    throw new Error("Ciphertext too short — corrupted or invalid");
  }

  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  let decrypted;
  try {
    decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
  } catch (err) {
    // AES-GCM auth tag failure — either wrong key or tampered ciphertext.
    // Do NOT reveal which one — just throw a generic error.
    throw new Error("Decryption failed: invalid key or tampered ciphertext");
  }

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Encrypt binary file data (ArrayBuffer).
 * @param {CryptoKey} key
 * @param {ArrayBuffer} fileBuffer
 * @returns {Promise<string>} base64-encoded(IV ∥ ciphertext ∥ authtag)
 */
export async function encryptFile(key, fileBuffer) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    fileBuffer
  );

  const combined = new Uint8Array(iv.byteLength + ciphertextBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertextBuffer), iv.byteLength);

  return bufferToBase64(combined);
}

/**
 * Decrypt file ciphertext back to an ArrayBuffer.
 * @param {CryptoKey} key
 * @param {string} base64Ciphertext
 * @returns {Promise<ArrayBuffer>}
 */
export async function decryptFile(key, base64Ciphertext) {
  const combined = base64ToBuffer(base64Ciphertext);

  if (combined.byteLength < 12 + 16) {
    throw new Error("Ciphertext too short — corrupted or invalid");
  }

  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  try {
    return await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
  } catch {
    throw new Error("Decryption failed: invalid key or tampered ciphertext");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL Hash Key Management
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a shareable URL with the encryption key in the fragment.
 * Fragment is NEVER sent by browsers in HTTP requests (RFC 3986 §3.5).
 * 
 * URL format: https://domain/view/<id>#<id>:<base64url-key>
 * 
 * @param {string} pasteId
 * @param {string} base64urlKey
 * @returns {string} full share URL
/**
 * Derive an AES-256 wrapping key from a passphrase and 128-bit salt using PBKDF2 (SHA-256).
 * Follows OWASP recommendations with 600,000 iterations.
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKeyFromPassphrase(passphrase, salt) {
  const encoder = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 600000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Wrap (encrypt) the master AES key using a user passphrase with PBKDF2 + AES-256-GCM.
 * @param {CryptoKey} masterKey
 * @param {string} passphrase
 * @returns {Promise<{ wrappedKeyB64: string, saltB64: string }>}
 */
export async function wrapKeyWithPassphrase(masterKey, passphrase) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16)); // 128-bit salt
  const wrappingKey = await deriveKeyFromPassphrase(passphrase, salt);
  const rawMasterKey = await window.crypto.subtle.exportKey("raw", masterKey);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV

  const wrappedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    rawMasterKey
  );

  const combined = new Uint8Array(iv.byteLength + wrappedBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(wrappedBuffer), iv.byteLength);

  return {
    wrappedKeyB64: bufferToBase64url(combined),
    saltB64: bufferToBase64url(salt),
  };
}

/**
 * Unwrap (decrypt) the master AES key using a user passphrase.
 * @param {string} wrappedKeyB64
 * @param {string} saltB64
 * @param {string} passphrase
 * @returns {Promise<CryptoKey>} Unwrapped master CryptoKey
 */
export async function unwrapKeyWithPassphrase(wrappedKeyB64, saltB64, passphrase) {
  const salt = base64urlToBuffer(saltB64);
  const wrappingKey = await deriveKeyFromPassphrase(passphrase, salt);
  const combined = base64urlToBuffer(wrappedKeyB64);

  if (combined.byteLength < 12 + 16) {
    throw new Error("Invalid wrapped key format");
  }

  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  let rawKeyBuffer;
  try {
    rawKeyBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      wrappingKey,
      ciphertext
    );
  } catch {
    throw new Error("Incorrect passphrase. Authentication failed.");
  }

  return window.crypto.subtle.importKey(
    "raw",
    rawKeyBuffer,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

/**
 * Build share URL for both standard and passphrase-protected notes.
 * @param {string} pasteId
 * @param {string} keyB64
 * @param {{ wrappedKeyB64: string, saltB64: string } | null} passphraseMeta
 * @returns {string}
 */
export function buildShareUrl(pasteId, keyB64, passphraseMeta = null) {
  const base = `${window.location.origin}/view/${pasteId}`;
  if (passphraseMeta) {
    return `${base}#${pasteId}:p:${passphraseMeta.wrappedKeyB64}:${passphraseMeta.saltB64}`;
  }
  return `${base}#${pasteId}:${keyB64}`;
}

/**
 * Parse the URL hash fragment to extract paste ID, key, or passphrase parameters.
 * @returns {{ id: string, isPassphraseProtected: boolean, keyB64?: string, wrappedKeyB64?: string, saltB64?: string } | null}
 */
export function parseShareHash() {
  const hash = window.location.hash.slice(1);
  if (!hash) return null;

  const parts = hash.split(":");
  if (parts.length < 2) return null;

  const id = parts[0];

  // Passphrase protected: #<id>:p:<wrappedKey>:<salt>
  if (parts[1] === "p" && parts.length >= 4) {
    return {
      id,
      isPassphraseProtected: true,
      wrappedKeyB64: parts[2],
      saltB64: parts[3],
    };
  }

  // Standard: #<id>:<keyB64>
  return {
    id,
    isPassphraseProtected: false,
    keyB64: parts[1],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoding Utilities
// ─────────────────────────────────────────────────────────────────────────────

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToBuffer(b64) {
  // Handle base64url by converting to standard base64
  const standard = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(standard);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bufferToBase64url(buffer) {
  return bufferToBase64(buffer)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function base64urlToBuffer(b64url) {
  // Pad to multiple of 4
  const padded = b64url + "=".repeat((4 - (b64url.length % 4)) % 4);
  return base64ToBuffer(padded);
}
