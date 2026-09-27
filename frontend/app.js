/**
 * OnceFlash — Secure Messenger Engine (app.js)
 * Clean, high-contrast, zero-knowledge browser cryptography.
 * Adheres strictly to OWASP Top 10 and SSDev / NIST SP 800-218 frameworks.
 *
 * Implements:
 * A. Anti-Bot "Click to Reveal" Screen
 * B. Secondary Passphrase Protection (PBKDF2 600,000 rounds + AES-256-GCM)
 * C. Live On-Screen Self-Destruct Timer (DOM memory wipe)
 * D. Client-Side QR Code Generator (100% in-browser SVG, zero external calls)
 * E. Anonymous Creator Read Receipt / Status Tracker
 * F. In-Browser Multi-File Bundle
 */

import {
  generateKey,
  exportKey,
  importKey,
  encrypt,
  decrypt,
  wrapKeyWithPassphrase,
  unwrapKeyWithPassphrase,
  buildShareUrl,
  parseShareHash,
} from "./crypto.js";

import { createPaste, fetchPaste, deletePaste, checkPasteStatus, fetchPasteInfo } from "./api.js";

// ─────────────────────────────────────────────────────────────────────────────
// Security Sanitization Helpers (OWASP A03: Injection & Path Traversal)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Strict filename sanitizer to prevent path traversal (../, ..\),
 * control characters, and file-based injection attacks.
 * @param {string} rawName
 * @returns {string} Sanitized base filename
 */
function sanitizeFilename(rawName) {
  if (!rawName || typeof rawName !== "string") return "attachment.bin";

  // Strip path traversal directory prefixes
  let clean = rawName.replace(/^.*[\\\/]/, "").trim();

  // Strip null bytes, control characters, and dangerous chars
  clean = clean.replace(/[\x00-\x1f\x7f]/g, "");
  clean = clean.replace(/[<>:"/\\|?*]/g, "_");

  // Prevent hidden file trick or empty name
  clean = clean.replace(/^\.+/, "");
  if (!clean) clean = "attachment.bin";

  // Limit filename length to 120 characters
  return clean.slice(0, 120);
}

/**
 * Escapes text for safe display (belt-and-suspenders).
 * @param {string} str
 * @returns {string}
 */
function escapeText(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Read File as Data URL asynchronously.
 * @param {File} file
 * @returns {Promise<string>}
 */
function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("Failed to read file from disk."));
    reader.readAsDataURL(file);
  });
}

/**
 * Convert a Base64 dataURL to a safe Blob.
 * @param {string} dataUrl
 * @param {string} mimeType
 * @returns {Blob}
 */
function dataUrlToBlob(dataUrl, mimeType = "application/octet-stream") {
  const parts = dataUrl.split(",");
  const base64Data = parts[1] || parts[0];
  const binaryString = atob(base64Data);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return new Blob([bytes], { type: mimeType });
}

/**
 * Pick an appropriate safe icon for file extensions.
 * @param {string} filename
 * @returns {string}
 */
function getFileIcon(filename) {
  const ext = (filename.split(".").pop() || "").toLowerCase();
  const iconMap = {
    pdf: "📄",
    doc: "📄",
    docx: "📄",
    txt: "📝",
    csv: "📊",
    xlsx: "📊",
    jpg: "🖼️",
    jpeg: "🖼️",
    png: "🖼️",
    gif: "🖼️",
    webp: "🖼️",
    zip: "📦",
    rar: "📦",
    tar: "📦",
    gz: "📦",
    mp3: "🎵",
    wav: "🎵",
    mp4: "🎬",
    mkv: "🎬",
  };
  return iconMap[ext] || "📎";
}

function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 ** 2).toFixed(2)} MB`;
}

function formatTtl(sec) {
  if (!sec || sec <= 0) return "expired";
  if (sec >= 86400) {
    const days = Math.floor(sec / 86400);
    const hrs = Math.floor((sec % 86400) / 3600);
    return hrs > 0 ? `${days}d ${hrs}h` : `${days} day${days > 1 ? "s" : ""}`;
  }
  if (sec >= 3600) {
    const hrs = Math.floor(sec / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    return mins > 0 ? `${hrs}h ${mins}m` : `${hrs} hour${hrs > 1 ? "s" : ""}`;
  }
  if (sec >= 60) {
    return `${Math.floor(sec / 60)} min`;
  }
  return `${sec} sec`;
}

function formatAutowipe(sec) {
  const n = parseInt(sec, 10);
  if (!n || n <= 0) return "Off (keep open)";
  if (n === 30) return "30 seconds";
  if (n === 60) return "60 seconds";
  if (n === 120) return "2 minutes";
  if (n === 300) return "5 minutes";
  if (n >= 60) {
    const m = Math.floor(n / 60);
    const s = n % 60;
    return s > 0 ? `${m}m ${s}s` : `${m} minute${m > 1 ? "s" : ""}`;
  }
  return `${n} seconds`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Toast Notification Utility
// ─────────────────────────────────────────────────────────────────────────────

function toast(message, type = "info", duration = 3200) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  const icon = type === "success" ? "✓" : type === "error" ? "✕" : "ℹ";
  const iconSpan = document.createElement("span");
  iconSpan.textContent = icon;
  const msgSpan = document.createElement("span");
  msgSpan.textContent = message;
  el.appendChild(iconSpan);
  el.appendChild(msgSpan);
  container.appendChild(el);

  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transform = "translateY(10px)";
    el.style.transition = "all 0.25s ease";
    setTimeout(() => el.remove(), 250);
  }, duration);
}

// ─────────────────────────────────────────────────────────────────────────────
// Panels Router
// ─────────────────────────────────────────────────────────────────────────────

const createPanel = document.getElementById("create-panel");
const sharePanel  = document.getElementById("share-panel");
const viewPanel   = document.getElementById("view-panel");

function showPanel(name) {
  if (createPanel) createPanel.style.display = (name === "create") ? "block" : "none";
  if (sharePanel)  sharePanel.style.display  = (name === "share")  ? "block" : "none";
  if (viewPanel)   viewPanel.style.display   = (name === "view")   ? "block" : "none";
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab Switching (Note / File)
// ─────────────────────────────────────────────────────────────────────────────

let activeTab = "text";
let attachedFiles = []; // Array of { file: File, id: string }
const MAX_TOTAL_BYTES = 5 * 1024 * 1024; // 5 MB total bundle limit

const tabTextBtn  = document.getElementById("tab-text-btn");
const tabFileBtn  = document.getElementById("tab-file-btn");
const textContent = document.getElementById("text-tab-content");
const fileContent = document.getElementById("file-tab-content");

if (tabTextBtn && tabFileBtn) {
  tabTextBtn.addEventListener("click", () => {
    activeTab = "text";
    tabTextBtn.classList.add("active");
    tabFileBtn.classList.remove("active");
    if (textContent) textContent.style.display = "block";
    if (fileContent) fileContent.style.display = "none";
  });

  tabFileBtn.addEventListener("click", () => {
    activeTab = "file";
    tabFileBtn.classList.add("active");
    tabTextBtn.classList.remove("active");
    if (textContent) textContent.style.display = "none";
    if (fileContent) fileContent.style.display = "block";
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Passphrase Toggle Handler
// ─────────────────────────────────────────────────────────────────────────────

const enablePassphraseCheckbox = document.getElementById("enable-passphrase");
const passphraseContainer       = document.getElementById("passphrase-container");
const notePassphraseInput       = document.getElementById("note-passphrase");

if (enablePassphraseCheckbox && passphraseContainer) {
  enablePassphraseCheckbox.addEventListener("change", () => {
    const isChecked = enablePassphraseCheckbox.checked;
    passphraseContainer.style.display = isChecked ? "block" : "none";
    if (isChecked && notePassphraseInput) {
      notePassphraseInput.focus();
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Character Counter & Dynamic Lifecycle Text
// ─────────────────────────────────────────────────────────────────────────────

const noteInput           = document.getElementById("note-input");
const charCount           = document.getElementById("char-count");
const maxViewsSelect      = document.getElementById("max-views-select");
const ttlSelect           = document.getElementById("ttl-select");
const screenAutowipeSelect = document.getElementById("screen-autowipe-select");
const lifecycleNote       = document.getElementById("lifecycle-note");

function updateLifecycleCaption() {
  if (!lifecycleNote || !maxViewsSelect || !ttlSelect) return;
  const views = maxViewsSelect.value;
  const viewsText = views === "1" ? "1 view" : `${views} views`;
  const ttlText = ttlSelect.options[ttlSelect.selectedIndex].text.toLowerCase();

  const strongViews = document.createElement("strong");
  strongViews.textContent = viewsText;
  const strongTtl = document.createElement("strong");
  strongTtl.textContent = ttlText;

  lifecycleNote.replaceChildren(
    document.createTextNode("The note will expire and be destroyed after "),
    strongViews,
    document.createTextNode(" or "),
    strongTtl,
    document.createTextNode(".")
  );
}

if (maxViewsSelect) maxViewsSelect.addEventListener("change", updateLifecycleCaption);
if (ttlSelect) ttlSelect.addEventListener("change", updateLifecycleCaption);
updateLifecycleCaption();

if (noteInput && charCount) {
  noteInput.addEventListener("input", () => {
    const len = noteInput.value.length;
    charCount.textContent = `${len.toLocaleString()} / 500,000`;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-File Dropzone Handler (Feature F: In-Browser Multi-File Bundle)
// ─────────────────────────────────────────────────────────────────────────────

const dropZone        = document.getElementById("drop-zone");
const fileInput       = document.getElementById("file-input");
const fileListPreview = document.getElementById("file-list-preview");

function renderFileList() {
  if (!fileListPreview) return;
  if (attachedFiles.length === 0) {
    fileListPreview.style.display = "none";
    fileListPreview.replaceChildren();
    return;
  }

  fileListPreview.style.display = "flex";
  fileListPreview.replaceChildren();

  let totalBytes = 0;
  attachedFiles.forEach((item, idx) => {
    totalBytes += item.file.size;
    const safeName = sanitizeFilename(item.file.name);
    const itemEl = document.createElement("div");
    itemEl.className = "file-chip-item";

    const infoWrap = document.createElement("div");
    infoWrap.style.display = "flex";
    infoWrap.style.alignItems = "center";
    infoWrap.style.gap = "8px";
    infoWrap.style.minWidth = "0";

    const iconSpan = document.createElement("span");
    iconSpan.textContent = getFileIcon(safeName);

    const nameStrong = document.createElement("strong");
    nameStrong.style.wordBreak = "break-all";
    nameStrong.style.color = "var(--text-bright)";
    nameStrong.textContent = safeName;

    const sizeSpan = document.createElement("span");
    sizeSpan.style.fontSize = "0.78rem";
    sizeSpan.style.color = "var(--text-muted)";
    sizeSpan.textContent = ` (${formatBytes(item.file.size)})`;

    infoWrap.appendChild(iconSpan);
    infoWrap.appendChild(nameStrong);
    infoWrap.appendChild(sizeSpan);

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn-danger";
    removeBtn.setAttribute("data-idx", String(idx));
    removeBtn.style.padding = "0.25rem 0.5rem";
    removeBtn.style.fontSize = "0.75rem";
    removeBtn.style.flexShrink = "0";
    removeBtn.textContent = "Remove";

    itemEl.appendChild(infoWrap);
    itemEl.appendChild(removeBtn);
    fileListPreview.appendChild(itemEl);
  });

  // Attach remove handlers
  const removeButtons = fileListPreview.querySelectorAll("button[data-idx]");
  removeButtons.forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const idx = parseInt(e.currentTarget.getAttribute("data-idx"), 10);
      attachedFiles.splice(idx, 1);
      renderFileList();
    });
  });
}

function handleFilesAdded(fileList) {
  const newFiles = Array.from(fileList);
  let currentTotal = attachedFiles.reduce((acc, f) => acc + f.file.size, 0);

  for (const f of newFiles) {
    if (currentTotal + f.size > MAX_TOTAL_BYTES) {
      toast(`Adding ${f.name} would exceed 5 MB total bundle limit`, "error");
      continue;
    }
    currentTotal += f.size;
    attachedFiles.push({ file: f, id: Math.random().toString(36).substring(2) });
  }

  renderFileList();
  if (fileInput) fileInput.value = "";
}

if (dropZone && fileInput) {
  dropZone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) handleFilesAdded(fileInput.files);
  });

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length) handleFilesAdded(e.dataTransfer.files);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Encrypt & Share Creation (Zero-Knowledge Envelope)
// ─────────────────────────────────────────────────────────────────────────────

const encryptBtn      = document.getElementById("encrypt-btn");
const encryptBtnLabel = document.getElementById("encrypt-btn-label");

let createdPasteId     = null;
let createdShareUrl    = null;
let createdStatusToken = null;
let viewedPasteId      = null; // set when recipient successfully decrypts

if (encryptBtn) {
  encryptBtn.addEventListener("click", async () => {
    const maxViews   = maxViewsSelect ? parseInt(maxViewsSelect.value, 10) : 1;
    const ttlSeconds = ttlSelect      ? parseInt(ttlSelect.value, 10)      : 86400;
    const selectEl   = document.getElementById("screen-autowipe-select");
    const autowipeSec = selectEl ? (parseInt(selectEl.value, 10) || 0) : 0;
    const isFile     = (activeTab === "file");

    if (isFile && attachedFiles.length === 0) {
      toast("Please select at least one file to encrypt", "error");
      return;
    }
    if (!isFile && (!noteInput || !noteInput.value.trim())) {
      toast("Please enter a note to encrypt", "error");
      return;
    }

    const isPassphraseProtected = enablePassphraseCheckbox && enablePassphraseCheckbox.checked;
    const enteredPassphrase = notePassphraseInput ? notePassphraseInput.value.trim() : "";

    if (isPassphraseProtected && !enteredPassphrase) {
      toast("Please enter a passphrase or uncheck the option", "error");
      if (notePassphraseInput) notePassphraseInput.focus();
      return;
    }

    encryptBtn.disabled = true;
    if (encryptBtnLabel) encryptBtnLabel.textContent = "Encrypting...";

    try {
      // 1. Generate fresh AES-256-GCM master key in browser CSPRNG
      const key = await generateKey();

      // 2. Assemble zero-knowledge payload envelope
      let payloadEnvelope;
      let contentType;

      if (isFile) {
        if (attachedFiles.length === 1) {
          const single = attachedFiles[0].file;
          const dataUrl = await readFileAsDataURL(single);
          const safeName = sanitizeFilename(single.name);
          payloadEnvelope = JSON.stringify({
            type: "file",
            filename: safeName,
            mime: single.type || "application/octet-stream",
            size: single.size,
            data: dataUrl,
            autowipe: autowipeSec,
          });
        } else {
          // Multi-file bundle
          const filesData = [];
          for (const item of attachedFiles) {
            const dataUrl = await readFileAsDataURL(item.file);
            filesData.push({
              filename: sanitizeFilename(item.file.name),
              mime: item.file.type || "application/octet-stream",
              size: item.file.size,
              data: dataUrl,
            });
          }
          payloadEnvelope = JSON.stringify({
            type: "files",
            files: filesData,
            autowipe: autowipeSec,
          });
        }
        contentType = "file";
      } else {
        payloadEnvelope = JSON.stringify({
          type: "text",
          content: noteInput.value,
          autowipe: autowipeSec,
        });
        contentType = "text";
      }

      // 3. Encrypt payload envelope with AES-256-GCM
      const ciphertext = await encrypt(key, payloadEnvelope);

      // 4. Handle secondary passphrase wrapping if enabled
      let passphraseMeta = null;
      let rawKeyB64 = null;

      if (isPassphraseProtected) {
        passphraseMeta = await wrapKeyWithPassphrase(key, enteredPassphrase);
      } else {
        rawKeyB64 = await exportKey(key);
      }

      // 5. Transmit ONLY ciphertext to backend (zero-knowledge)
      const result = await createPaste(ciphertext, { maxViews, ttlSeconds, contentType, autowipe: autowipeSec });

      // 6. Build zero-knowledge share URL (key fragment never sent over wire)
      const shareUrl = buildShareUrl(result.id, rawKeyB64, passphraseMeta);
      createdPasteId     = result.id;
      createdShareUrl    = shareUrl;
      createdStatusToken = result.status_token;

      // Show share screen
      showShareScreen(shareUrl, maxViews, result.expires_at, isPassphraseProtected, autowipeSec);

    } catch (err) {
      console.error("Encryption error:", err);
      toast(err.message || "Failed to create note", "error");
    } finally {
      encryptBtn.disabled = false;
      if (encryptBtnLabel) encryptBtnLabel.textContent = "Create Note";
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Share Result Screen & Feature D (QR) / Feature E (Status Tracker)
// ─────────────────────────────────────────────────────────────────────────────

const qrContainer      = document.getElementById("qr-container");
const qrMount          = document.getElementById("qr-mount");
const toggleQrBtn      = document.getElementById("toggle-qr-btn");
const checkStatusBtn   = document.getElementById("check-status-btn");
const statusContainer  = document.getElementById("status-container");
const statusBadge      = document.getElementById("status-badge");
const statusDetail     = document.getElementById("status-detail");

function showShareScreen(url, maxViews, expiresAt, isProtected, autowipeSec = 0) {
  const shareUrlInput  = document.getElementById("share-url");
  const metaViewsEl    = document.getElementById("meta-views");
  const metaExpiryEl   = document.getElementById("meta-expires");
  const metaAutowipeEl = document.getElementById("meta-autowipe");

  if (shareUrlInput) shareUrlInput.value = url;
  if (metaViewsEl) {
    const protTag = isProtected ? " (Passphrase protected)" : "";
    metaViewsEl.textContent = (maxViews === 1) ? `1 view (burns on read)${protTag}` : `${maxViews} views${protTag}`;
  }

  if (metaExpiryEl) {
    const expDate = new Date(expiresAt * 1000);
    metaExpiryEl.textContent = expDate.toLocaleString(undefined, {
      dateStyle: "medium", timeStyle: "short"
    });
  }

  if (metaAutowipeEl) {
    metaAutowipeEl.textContent = formatAutowipe(autowipeSec);
  }

  if (qrContainer) qrContainer.style.display = "none";
  if (statusContainer) statusContainer.style.display = "none";

  showPanel("share");
  toast("Encrypted secret ready to share!", "success");
}

// Feature D: Client-Side In-Browser QR Code Generator
if (toggleQrBtn && qrMount && qrContainer) {
  toggleQrBtn.addEventListener("click", () => {
    if (qrContainer.style.display === "block") {
      qrContainer.style.display = "none";
      toggleQrBtn.textContent = "Show QR Code";
      return;
    }

    if (!createdShareUrl) return;

    if (window.QRCodeGenerator && typeof window.QRCodeGenerator.generateSVG === "function") {
      try {
        const svgMarkup = window.QRCodeGenerator.generateSVG(createdShareUrl, 4);
        const parser = new DOMParser();
        const svgDoc = parser.parseFromString(svgMarkup, "image/svg+xml");
        const svgEl = svgDoc.documentElement;
        qrMount.replaceChildren(svgEl);
        qrContainer.style.display = "block";
        toggleQrBtn.textContent = "Hide QR Code";
      } catch (err) {
        console.error("QR Code Error:", err);
        toast("Failed to render QR Code locally", "error");
      }
    } else {
      toast("QR Code generator not available", "error");
    }
  });
}

// Feature E: Anonymous Creator Read Receipt / Status Tracker
if (checkStatusBtn && statusContainer && statusBadge && statusDetail) {
  checkStatusBtn.addEventListener("click", async () => {
    if (!createdPasteId || !createdStatusToken) {
      toast("No active note to track", "info");
      return;
    }

    statusContainer.style.display = "block";
    statusBadge.className = "badge-status";
    statusBadge.textContent = "CHECKING...";
    statusDetail.textContent = "Querying note status...";

    try {
      const res = await checkPasteStatus(createdPasteId, createdStatusToken);
      if (res.status === "waiting" || res.status === "unread") {
        statusBadge.className = "badge-status waiting";
        statusBadge.textContent = "WAITING";
        statusDetail.textContent = `Not opened yet. Views remaining: ${res.views_left}. Expires in ${Math.round((res.ttl_left || 0) / 60)} minutes.`;
      } else if (res.status === "opened") {
        statusBadge.className = "badge-status opened";
        statusBadge.textContent = "OPENED";
        statusDetail.textContent = res.message || "The recipient opened and read this note";
      } else if (res.status === "destroyed") {
        statusBadge.className = "badge-status destroyed";
        statusBadge.textContent = "DESTROYED";
        statusDetail.textContent = res.message || "destroyed before anyone opened it";
      } else {
        statusBadge.className = "badge-status";
        statusBadge.textContent = (res.status || "UNKNOWN").toUpperCase();
        statusDetail.textContent = res.message || `Views remaining: ${res.views_left || 0}`;
      }
    } catch (err) {
      statusBadge.className = "badge-status destroyed";
      statusBadge.textContent = "DESTROYED";
      statusDetail.textContent = "destroyed before anyone opened it";
    }
  });
}

// Copy URL Button
const copyUrlBtn = document.getElementById("copy-url-btn");
if (copyUrlBtn) {
  copyUrlBtn.addEventListener("click", async () => {
    const shareUrlInput = document.getElementById("share-url");
    if (!shareUrlInput) return;
    try {
      await navigator.clipboard.writeText(shareUrlInput.value);
      copyUrlBtn.textContent = "Copied!";
      toast("Link copied to clipboard!", "success");
      setTimeout(() => {
        copyUrlBtn.textContent = "Copy Link";
      }, 2000);
    } catch {
      shareUrlInput.select();
      toast("Press Ctrl+C to copy the link", "info");
    }
  });
}

// Create Another Note Button
const newNoteBtn = document.getElementById("new-note-btn");
if (newNoteBtn) {
  newNoteBtn.addEventListener("click", () => {
    if (noteInput) noteInput.value = "";
    if (charCount) charCount.textContent = "0 / 500,000";
    if (notePassphraseInput) notePassphraseInput.value = "";
    if (enablePassphraseCheckbox) enablePassphraseCheckbox.checked = false;
    if (passphraseContainer) passphraseContainer.style.display = "none";
    if (screenAutowipeSelect) screenAutowipeSelect.value = "0";
    attachedFiles = [];
    renderFileList();
    createdPasteId     = null;
    createdShareUrl    = null;
    createdStatusToken = null;
    showPanel("create");
  });
}

// Destroy Note Now Button
const burnNowBtn = document.getElementById("burn-now-btn");
if (burnNowBtn) {
  burnNowBtn.addEventListener("click", async () => {
    if (!createdPasteId) return;
    const confirmBurn = window.confirm("Are you sure? This will permanently delete the encrypted note from the server immediately.");
    if (!confirmBurn) return;

    try {
      await deletePaste(createdPasteId);
      toast("Note permanently destroyed.", "success");
      const statusBadge = document.getElementById("status-badge");
      const statusDetail = document.getElementById("status-detail");
      const statusContainer = document.getElementById("status-container");
      if (statusContainer) statusContainer.style.display = "block";
      if (statusBadge) {
        statusBadge.className = "badge-status destroyed";
        statusBadge.textContent = "DESTROYED";
      }
      if (statusDetail) {
        statusDetail.textContent = "destroyed before anyone opened it";
      }
    } catch (err) {
      toast(err.message || "Failed to destroy note", "error");
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Feature A: Anti-Bot Interstitial & Recipient Decryption
// ─────────────────────────────────────────────────────────────────────────────

let burnTimerInterval = null;

function startLiveBurnTimer(seconds) {
  const banner = document.getElementById("burn-timer-banner");
  const textEl = document.getElementById("burn-timer-text");
  if (!banner || !textEl || seconds <= 0) return;

  banner.style.display = "flex";
  let timeLeft = seconds;

  textEl.textContent = `Auto-wiping screen in ${timeLeft}s to prevent shoulder-surfing...`;

  if (burnTimerInterval) clearInterval(burnTimerInterval);

  burnTimerInterval = setInterval(() => {
    timeLeft--;
    if (timeLeft > 0) {
      textEl.textContent = `Auto-wiping screen in ${timeLeft}s to prevent shoulder-surfing...`;
    } else {
      clearInterval(burnTimerInterval);
      burnTimerInterval = null;
      // Feature C: DOM Memory Purge
      purgeDecryptedMemory();
      // Notify server so receipt changes from opened to destroyed
      if (viewedPasteId) {
        const pid = viewedPasteId;
        viewedPasteId = null;
        deletePaste(pid).catch(() => {});
      }
    }
  }, 1000);
}

function purgeDecryptedMemory() {
  const textEl = document.getElementById("decrypted-text");
  const fileContainer = document.getElementById("decrypted-files-container");
  const banner = document.getElementById("burn-timer-banner");
  const textElBanner = document.getElementById("burn-timer-text");

  if (textEl) textEl.textContent = "[WIPED FOR SECURITY]";
  if (fileContainer) {
    const purgeMsg = document.createElement("div");
    purgeMsg.style.padding = "1.5rem";
    purgeMsg.style.textAlign = "center";
    purgeMsg.style.color = "var(--text-muted)";
    purgeMsg.style.fontSize = "0.9rem";
    purgeMsg.textContent = "File attachment memory has been purged to prevent unauthorized exposure.";
    fileContainer.replaceChildren(purgeMsg);
  }
  if (banner && textElBanner) {
    banner.style.background = "rgba(248, 81, 73, 0.15)";
    banner.style.borderColor = "rgba(248, 81, 73, 0.3)";
    textElBanner.style.color = "var(--accent-red)";
    textElBanner.textContent = "Screen memory wiped. Note content has been permanently erased.";
  }
  toast("Screen wiped for your security", "info");
}

async function initViewPage() {
  showPanel("view");

  const viewInterstitial = document.getElementById("view-interstitial");
  const viewLoading      = document.getElementById("view-loading");
  const viewError        = document.getElementById("view-error");
  const viewSuccess      = document.getElementById("view-success");
  const revealBtn        = document.getElementById("reveal-btn");
  const passphraseWrap   = document.getElementById("recipient-passphrase-wrap");
  const recipientPassInput = document.getElementById("recipient-passphrase-input");

  function renderError(title, desc) {
    if (viewInterstitial) viewInterstitial.style.display = "none";
    if (viewLoading)      viewLoading.style.display      = "none";
    if (viewSuccess)      viewSuccess.style.display      = "none";
    if (viewError)        viewError.style.display        = "block";

    const titleEl = document.getElementById("view-error-title");
    const descEl  = document.getElementById("view-error-desc");
    if (titleEl) titleEl.textContent = title;
    if (descEl)  descEl.textContent  = desc;
  }

  // Parse fragment (#id:key or #id:p:wrappedKey:salt)
  const parsed = parseShareHash();
  if (!parsed) {
    renderError(
      "Missing Decryption Key",
      "The link is missing the decryption key fragment (#). Please ensure you copied the complete URL."
    );
    return;
  }

  const { id, isPassphraseProtected } = parsed;

  const viewsEl = document.getElementById("interstitial-views");
  const expiresEl = document.getElementById("interstitial-expires");
  const burnNoticeEl = document.getElementById("interstitial-burn-notice");

  // Fetch non-destructive envelope metadata before revealing
  fetchPasteInfo(id)
    .then((info) => {
      if (viewsEl) {
        viewsEl.textContent = info.views_left <= 1 ? "1 view (burn on read)" : `${info.views_left} views remaining`;
      }
      if (expiresEl) {
        expiresEl.textContent = `in ${formatTtl(info.ttl_left)}`;
      }
      if (burnNoticeEl) {
        burnNoticeEl.textContent = formatAutowipe(info.autowipe);
      }
    })
    .catch(() => {
      renderError(
        "Note not found",
        "This note has already been read, destroyed, or has expired."
      );
    });

  // Show Anti-Bot Interstitial card (Feature A)
  // Crawler bots will stop here without fetching/burning the note!
  if (viewInterstitial) {
    viewInterstitial.style.display = "block";
    if (viewLoading) viewLoading.style.display = "none";
    if (viewError)   viewError.style.display   = "none";
    if (viewSuccess) viewSuccess.style.display = "none";
  }

  if (isPassphraseProtected && passphraseWrap) {
    passphraseWrap.style.display = "block";
    if (recipientPassInput) recipientPassInput.focus();
  }

  if (!revealBtn) return;

  // Single-fire handler for "🔥 Decrypt & Read"
  revealBtn.onclick = async () => {
    let key;

    // Feature B: Unwrapping with Secondary Passphrase
    if (isPassphraseProtected) {
      const enteredPass = recipientPassInput ? recipientPassInput.value.trim() : "";
      if (!enteredPass) {
        toast("Passphrase is required to unlock this note", "error");
        if (recipientPassInput) recipientPassInput.focus();
        return;
      }

      revealBtn.disabled = true;
      revealBtn.textContent = "Unwrapping Key...";

      try {
        key = await unwrapKeyWithPassphrase(parsed.wrappedKeyB64, parsed.saltB64, enteredPass);
      } catch (err) {
        revealBtn.disabled = false;
        revealBtn.textContent = "Decrypt & Read Message";
        toast("Incorrect passphrase. Authentication failed.", "error");
        if (recipientPassInput) {
          recipientPassInput.value = "";
          recipientPassInput.focus();
        }
        return;
      }
    } else {
      // Standard direct key import
      try {
        key = await importKey(parsed.keyB64);
      } catch {
        renderError("Invalid Key", "The decryption key in the link is malformed or corrupted.");
        return;
      }
    }

    // Now transition to loading & retrieve from backend
    if (viewInterstitial) viewInterstitial.style.display = "none";
    if (viewLoading) viewLoading.style.display = "block";

    try {
      // 1. Retrieve ciphertext (only ID sent — key stays strictly in browser)
      const data = await fetchPaste(id);

      // 2. Decrypt client-side
      let rawDecrypted;
      try {
        rawDecrypted = await decrypt(key, data.ciphertext);
      } catch {
        renderError("Decryption Failed", "The note could not be decrypted. It may have been tampered with or corrupted.");
        return;
      }

      // 3. Parse zero-knowledge envelope
      let payload;
      try {
        payload = JSON.parse(rawDecrypted);
      } catch {
        payload = { type: "text", content: rawDecrypted };
      }

      const textSection   = document.getElementById("decrypted-text-section");
      const fileSection   = document.getElementById("decrypted-file-section");
      const fileContainer = document.getElementById("decrypted-files-container");
      const viewTitle     = document.getElementById("view-title");

      if (payload.type === "file" || payload.type === "files") {
        // ─── FILE(S) DECRYPTED ───
        if (viewTitle) viewTitle.textContent = (payload.type === "files") ? "Decrypted Files Bundle" : "Decrypted File";
        if (textSection) textSection.style.display = "none";
        if (fileSection) fileSection.style.display = "block";

        const filesToRender = (payload.type === "files" && Array.isArray(payload.files))
          ? payload.files
          : [{ filename: payload.filename, mime: payload.mime, size: payload.size, data: payload.data }];

        if (fileContainer) {
          fileContainer.replaceChildren();
          filesToRender.forEach((f) => {
            const safeName = sanitizeFilename(f.filename);
            const safeMime = f.mime || "application/octet-stream";
            const sizeText = formatBytes(f.size || 0);

            const card = document.createElement("div");
            card.className = "file-display-card";

            const blob = dataUrlToBlob(f.data, safeMime);
            const blobUrl = URL.createObjectURL(blob);

            const header = document.createElement("div");
            header.className = "file-display-header";

            const iconEl = document.createElement("div");
            iconEl.className = "file-display-icon";
            iconEl.textContent = getFileIcon(safeName);

            const metaEl = document.createElement("div");
            metaEl.className = "file-display-meta";

            const nameEl = document.createElement("div");
            nameEl.className = "file-display-name";
            nameEl.textContent = safeName;

            const subEl = document.createElement("div");
            subEl.className = "file-display-sub";
            const sizeSpan = document.createElement("span");
            sizeSpan.textContent = sizeText;
            const bullet = document.createTextNode(" • ");
            const mimeSpan = document.createElement("span");
            mimeSpan.textContent = safeMime;
            subEl.appendChild(sizeSpan);
            subEl.appendChild(bullet);
            subEl.appendChild(mimeSpan);

            metaEl.appendChild(nameEl);
            metaEl.appendChild(subEl);

            const downloadLink = document.createElement("a");
            downloadLink.href = blobUrl;
            downloadLink.download = safeName;
            downloadLink.className = "btn-primary";
            downloadLink.style.textDecoration = "none";
            downloadLink.style.marginLeft = "auto";
            downloadLink.textContent = "Download";

            header.appendChild(iconEl);
            header.appendChild(metaEl);
            header.appendChild(downloadLink);
            card.appendChild(header);

            const isSafeImage = safeMime.startsWith("image/") && safeMime !== "image/svg+xml";
            if (isSafeImage) {
              const imgWrap = document.createElement("div");
              imgWrap.className = "file-preview-img-container";
              const img = document.createElement("img");
              img.src = blobUrl;
              img.className = "file-preview-img";
              img.alt = "Decrypted preview";
              imgWrap.appendChild(img);
              card.appendChild(imgWrap);
            }

            fileContainer.appendChild(card);
          });
        }

      } else {
        // ─── TEXT DECRYPTED ───
        if (viewTitle) viewTitle.textContent = "Decrypted Note";
        if (fileSection) fileSection.style.display = "none";
        if (textSection) textSection.style.display = "block";

        // SECURITY CRITICAL (OWASP A03 Stored XSS): Render strictly via textContent
        const decryptedEl = document.getElementById("decrypted-text");
        if (decryptedEl) {
          decryptedEl.textContent = payload.content || "";
        }
      }

      // Update views left badge
      const viewsLeft = data.views_left;
      const viewsBadge = document.getElementById("view-views-left");
      if (viewsBadge) {
        viewsBadge.textContent = (viewsLeft <= 0) ? "Burned on read" : `${viewsLeft} views left`;
      }

      if (viewLoading) viewLoading.style.display = "none";
      if (viewSuccess) viewSuccess.style.display = "block";

      // Feature C: Auto-wipe screen countdown if enabled in envelope
      if (payload.autowipe && payload.autowipe > 0) {
        startLiveBurnTimer(payload.autowipe);
      }

      // Store paste ID so receiver Destroy button can revoke remaining views
      viewedPasteId = id;

      // Clean fragment from address bar for privacy
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, "", window.location.pathname);
      }

    } catch (err) {
      renderError(
        "Note Not Found",
        err.message || "This note has already been read, destroyed, or has expired."
      );
    }
  };
}

// Copy decrypted text button
const copyDecryptedBtn = document.getElementById("copy-decrypted-btn");
if (copyDecryptedBtn) {
  copyDecryptedBtn.addEventListener("click", async () => {
    const textEl = document.getElementById("decrypted-text");
    if (!textEl) return;
    try {
      await navigator.clipboard.writeText(textEl.textContent);
      copyDecryptedBtn.textContent = "Copied!";
      toast("Text copied to clipboard", "success");
      setTimeout(() => {
        copyDecryptedBtn.textContent = "Copy Text";
      }, 2000);
    } catch {
      toast("Failed to copy to clipboard", "error");
    }
  });
}

// ─── Receiver Destroy Note Buttons ───────────────────────────────────────────
// Allow recipients to burn remaining views of multi-view notes.
// For single-view notes the paste is already gone — we just inform them.
async function handleReceiverDestroy() {
  const confirmed = window.confirm("Destroy this note? Screen memory will be wiped and no further access will be possible.");
  if (!confirmed) return;

  // Immediately cancel any active countdown timer so it doesn't keep running
  if (burnTimerInterval) {
    clearInterval(burnTimerInterval);
    burnTimerInterval = null;
  }

  // Wipe screen DOM memory immediately
  purgeDecryptedMemory();
  toast("Note permanently destroyed.", "success");

  const pid = viewedPasteId;
  viewedPasteId = null;

  if (pid) {
    try {
      await deletePaste(pid);
    } catch {
      // Best-effort
    }
  }
}

const receiverDestroyBtn     = document.getElementById("receiver-destroy-btn");
const receiverDestroyBtnFile = document.getElementById("receiver-destroy-btn-file");
if (receiverDestroyBtn)     receiverDestroyBtn.addEventListener("click", handleReceiverDestroy);
if (receiverDestroyBtnFile) receiverDestroyBtnFile.addEventListener("click", handleReceiverDestroy);

// ─────────────────────────────────────────────────────────────────────────────
// Initial Route Detection
// ─────────────────────────────────────────────────────────────────────────────

const initialPath = window.location.pathname;
if (initialPath.startsWith("/view/")) {
  initViewPage();
} else {
  showPanel("create");
}
