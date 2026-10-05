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
  importRoomKey,
  buildRoomUrl,
  parseRoomHash,
} from "./crypto.js?v=2.3";

import {
  createPaste,
  fetchPaste,
  deletePaste,
  checkPasteStatus,
  fetchPasteInfo,
  createRoom,
  startRoom,
  fetchRoomInfo,
  joinRoom,
  sendRoomMessage,
  fetchRoomMessages,
  destroyRoom,
} from "./api.js";

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
// Custom Confirmation Modal (Zero Glassmorphism, Clean Solid Pro UI, No Emoji)
// ─────────────────────────────────────────────────────────────────────────────

function showConfirmModal({
  title = "Confirm Action",
  tag = "[ CONFIRM ACTION ]",
  message = "Are you sure you want to proceed?",
  confirmText = "Confirm",
  cancelText = "Cancel",
  danger = true,
} = {}) {
  return new Promise((resolve) => {
    const modal = document.getElementById("confirm-modal");
    const titleEl = document.getElementById("confirm-modal-title");
    const tagEl = document.getElementById("confirm-modal-tag");
    const msgEl = document.getElementById("confirm-modal-message");
    const okBtn = document.getElementById("confirm-modal-ok-btn");
    const cancelBtn = document.getElementById("confirm-modal-cancel-btn");

    if (!modal) {
      return resolve(window.confirm(message));
    }

    if (titleEl) titleEl.textContent = title;
    if (tagEl) {
      tagEl.textContent = tag;
      tagEl.style.color = danger ? "#ff7b72" : "var(--brand-cyan, #00ffc8)";
    }
    if (msgEl) msgEl.textContent = message;
    if (okBtn) {
      okBtn.textContent = confirmText;
      okBtn.className = danger ? "btn-danger" : "btn-primary";
    }
    if (cancelBtn) cancelBtn.textContent = cancelText;

    const cleanup = () => {
      modal.style.display = "none";
      document.removeEventListener("keydown", keyHandler);
      okBtn?.removeEventListener("click", onOk);
      cancelBtn?.removeEventListener("click", onCancel);
      modal.removeEventListener("click", onBackdrop);
    };

    const onOk = () => { cleanup(); resolve(true); };
    const onCancel = () => { cleanup(); resolve(false); };
    const onBackdrop = (e) => {
      if (e.target === modal) { cleanup(); resolve(false); }
    };
    const keyHandler = (e) => {
      if (e.key === "Escape") { cleanup(); resolve(false); }
      if (e.key === "Enter" && document.activeElement !== cancelBtn) {
        e.preventDefault();
        cleanup();
        resolve(true);
      }
    };

    okBtn?.addEventListener("click", onOk);
    cancelBtn?.addEventListener("click", onCancel);
    modal.addEventListener("click", onBackdrop);
    document.addEventListener("keydown", keyHandler);

    modal.style.display = "flex";
    okBtn?.focus();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Panels Router
// ─────────────────────────────────────────────────────────────────────────────

const createPanel    = document.getElementById("create-panel");
const sharePanel     = document.getElementById("share-panel");
const viewPanel      = document.getElementById("view-panel");
const roomSharePanel = document.getElementById("room-share-panel");
const roomChatPanel  = document.getElementById("room-chat-panel");

function showPanel(name) {
  if (createPanel)    createPanel.style.display    = (name === "create")     ? "block" : "none";
  if (sharePanel)     sharePanel.style.display     = (name === "share")      ? "block" : "none";
  if (viewPanel)      viewPanel.style.display      = (name === "view")       ? "block" : "none";
  if (roomSharePanel) roomSharePanel.style.display = (name === "room-share") ? "block" : "none";
  if (roomChatPanel)  roomChatPanel.style.display  = (name === "room-chat")  ? "block" : "none";
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab Switching (Note / File / Flash Room)
// ─────────────────────────────────────────────────────────────────────────────

let activeTab = "text";
let attachedFiles = []; // Array of { file: File, id: string }
const MAX_TOTAL_BYTES = 5 * 1024 * 1024; // 5 MB total bundle limit

const tabTextBtn       = document.getElementById("tab-text-btn");
const tabFileBtn       = document.getElementById("tab-file-btn");
const tabRoomBtn       = document.getElementById("tab-room-btn");
const textContent      = document.getElementById("text-tab-content");
const fileContent      = document.getElementById("file-tab-content");
const roomContent      = document.getElementById("room-tab-content");
const noteFileControls = document.getElementById("note-file-controls");

if (tabTextBtn && tabFileBtn && tabRoomBtn) {
  tabTextBtn.addEventListener("click", () => {
    activeTab = "text";
    tabTextBtn.classList.add("active");
    tabFileBtn.classList.remove("active");
    tabRoomBtn.classList.remove("active");
    if (textContent) textContent.style.display = "block";
    if (fileContent) fileContent.style.display = "none";
    if (roomContent) roomContent.style.display = "none";
    if (noteFileControls) noteFileControls.style.display = "block";
    const cc = document.getElementById("char-count");
    if (cc) cc.style.display = "inline";
  });

  tabFileBtn.addEventListener("click", () => {
    activeTab = "file";
    tabFileBtn.classList.add("active");
    tabTextBtn.classList.remove("active");
    tabRoomBtn.classList.remove("active");
    if (textContent) textContent.style.display = "none";
    if (fileContent) fileContent.style.display = "block";
    if (roomContent) roomContent.style.display = "none";
    if (noteFileControls) noteFileControls.style.display = "block";
    const cc = document.getElementById("char-count");
    if (cc) cc.style.display = "none";
  });

  tabRoomBtn.addEventListener("click", () => {
    activeTab = "room";
    tabRoomBtn.classList.add("active");
    tabTextBtn.classList.remove("active");
    tabFileBtn.classList.remove("active");
    if (textContent) textContent.style.display = "none";
    if (fileContent) fileContent.style.display = "none";
    if (roomContent) roomContent.style.display = "block";
    if (noteFileControls) noteFileControls.style.display = "none";
    const cc = document.getElementById("char-count");
    if (cc) cc.style.display = "none";
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
    const confirmBurn = await showConfirmModal({
      title: "Destroy Note Permanently",
      tag: "[ PERMANENT PURGE ]",
      message: "Are you sure? This will permanently delete the encrypted note from the server immediately.",
      confirmText: "Destroy Note",
      cancelText: "Cancel",
      danger: true,
    });
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
  const confirmed = await showConfirmModal({
    title: "Destroy Note",
    tag: "[ CLIENT PURGE ]",
    message: "Destroy this note? Screen memory will be wiped and no further access will be possible.",
    confirmText: "Destroy Note",
    cancelText: "Cancel",
    danger: true,
  });
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
// Flash Room Ephemeral Live Chat Engine
// Zero-knowledge, in-memory, auto-purging live communication
// ─────────────────────────────────────────────────────────────────────────────

let currentRoom = null;

function purgeRoomMemory() {
  if (currentRoom) {
    if (currentRoom.pollTimer) {
      clearInterval(currentRoom.pollTimer);
      currentRoom.pollTimer = null;
    }
    if (currentRoom.countdownTimer) {
      clearInterval(currentRoom.countdownTimer);
      currentRoom.countdownTimer = null;
    }
    currentRoom.cryptoKey = null;
    currentRoom.keyB64 = null;
    currentRoom.adminToken = null;
    currentRoom.clientToken = null;
    currentRoom.isDestroyed = true;
    currentRoom = null;
  }
  const msgContainer = document.getElementById("room-messages-container");
  if (msgContainer) {
    msgContainer.replaceChildren();
  }
}

function showRoomDestroyed(message = "This session has been terminated. All messages have been wiped from memory and local crypto keys have been discarded.") {
  purgeRoomMemory();
  const joinView = document.getElementById("room-join-interstitial");
  const activeView = document.getElementById("room-chat-active");
  const destroyedView = document.getElementById("room-destroyed-screen");
  const descEl = document.getElementById("room-destroyed-desc");

  if (joinView) joinView.style.display = "none";
  if (activeView) activeView.style.display = "none";
  if (descEl) descEl.textContent = message;
  if (destroyedView) destroyedView.style.display = "block";
  showPanel("room-chat");
}

function appendSystemMessage(text) {
  const container = document.getElementById("room-messages-container");
  if (!container) return;

  const lastChild = container.lastElementChild;
  if (lastChild && lastChild.dataset.sysMsg === text) {
    return;
  }

  const line = document.createElement("div");
  line.className = "kali-sys-line";
  line.dataset.sysMsg = text;

  const icon = document.createElement("span");
  icon.className = "kali-sys-icon";
  icon.textContent = "[*]";

  const txt = document.createElement("span");
  txt.textContent = ` ${text}`;

  line.appendChild(icon);
  line.appendChild(txt);
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

const memberColorMap = new Map(); // sender -> { isHost, guestIndex }
const seenGuestsList = [];

function getMemberColorClass(sender, isHost, guestIndex) {
  if (isHost || guestIndex === 0) return "color-red";
  if (guestIndex === 1) return "color-blue";
  if (guestIndex === 2) return "color-yellow";
  if (guestIndex === 3) return "color-green";

  if (sender && memberColorMap.has(sender)) {
    const info = memberColorMap.get(sender);
    if (info.isHost || info.guestIndex === 0) return "color-red";
    if (info.guestIndex === 1) return "color-blue";
    if (info.guestIndex === 2) return "color-yellow";
    if (info.guestIndex === 3) return "color-green";
  }

  if (sender) {
    let idx = seenGuestsList.indexOf(sender);
    if (idx === -1) {
      seenGuestsList.push(sender);
      idx = seenGuestsList.length - 1;
    }
    const fallbackIdx = idx + 1;
    if (fallbackIdx === 1) return "color-blue";
    if (fallbackIdx === 2) return "color-yellow";
    if (fallbackIdx === 3) return "color-green";
  }

  return "color-blue";
}

function appendChatMessage(sender, text, timestamp, isHostMsg, guestIndexMsg) {
  const container = document.getElementById("room-messages-container");
  if (!container) return;

  const sig = `${sender}_${timestamp}_${text}`;
  const lastChild = container.lastElementChild;
  if (lastChild && lastChild.dataset.msgSig === sig) {
    return; // Prevent duplicate rendering of identical message
  }

  const isSelf = currentRoom && (sender === currentRoom.myAlias);
  const isHost = (isHostMsg !== undefined) ? isHostMsg : (isSelf ? currentRoom.isHost : false);
  const guestIndex = (guestIndexMsg !== undefined) ? guestIndexMsg : (isSelf ? currentRoom.guestIndex : undefined);

  if (sender) {
    memberColorMap.set(sender, {
      isHost,
      guestIndex: (guestIndex !== undefined) ? guestIndex : (isHost ? 0 : undefined),
    });
  }

  const colorClass = getMemberColorClass(sender, isHost, guestIndex);
  const role = isSelf ? (currentRoom.isHost ? "host" : "you") : (isHost ? "host" : "peer");

  const block = document.createElement("div");
  block.className = "kali-msg-block";
  block.dataset.msgSig = sig;

  const promptLine = document.createElement("div");
  promptLine.className = "kali-msg-prompt";

  const corner = document.createElement("span");
  corner.className = "kali-prompt-corner";
  corner.textContent = "┌──(";

  const userTag = document.createElement("span");
  userTag.className = `kali-user-tag ${colorClass}`;
  userTag.textContent = sender;

  const icon = document.createElement("span");
  icon.className = `kali-prompt-icon ${colorClass}`;
  icon.textContent = "㉿";

  const roleTag = document.createElement("span");
  roleTag.className = `kali-prompt-role ${colorClass}`;
  roleTag.textContent = role;

  const closeParen = document.createElement("span");
  closeParen.className = "kali-prompt-corner";
  closeParen.textContent = ")-[";

  const dirTag = document.createElement("span");
  dirTag.className = "kali-prompt-dir";
  dirTag.textContent = "~/room";

  const endBracket = document.createElement("span");
  endBracket.className = "kali-prompt-corner";
  endBracket.textContent = "]";

  const timeSpan = document.createElement("span");
  timeSpan.className = "kali-msg-time";
  timeSpan.textContent = timestamp
    ? `[${new Date(timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}]`
    : `[${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}]`;

  promptLine.appendChild(corner);
  promptLine.appendChild(userTag);
  promptLine.appendChild(icon);
  promptLine.appendChild(roleTag);
  promptLine.appendChild(closeParen);
  promptLine.appendChild(dirTag);
  promptLine.appendChild(endBracket);
  promptLine.appendChild(timeSpan);

  const bodyLine = document.createElement("div");
  bodyLine.className = "kali-msg-body";

  const arrow = document.createElement("span");
  arrow.className = `kali-arrow ${colorClass}`;
  arrow.textContent = "└─$";

  const textSpan = document.createElement("span");
  textSpan.className = "kali-text";
  textSpan.textContent = text;

  bodyLine.appendChild(arrow);
  bodyLine.appendChild(textSpan);

  block.appendChild(promptLine);
  block.appendChild(bodyLine);

  container.appendChild(block);
  container.scrollTop = container.scrollHeight;
}

function startRoomCountdown() {
  if (!currentRoom) return;
  if (currentRoom.countdownTimer) clearInterval(currentRoom.countdownTimer);

  const timerBadge = document.getElementById("room-timer-badge");

  const tick = () => {
    if (!currentRoom || currentRoom.isDestroyed) return;
    const pad = (n) => String(n).padStart(2, "0");

    if (!currentRoom.started || !currentRoom.expiresAt) {
      const dur = currentRoom.durationSeconds || 600;
      const m = Math.floor(dur / 60);
      const s = dur % 60;
      if (timerBadge) {
        timerBadge.textContent = `[PENDING: ${pad(m)}:${pad(s)}]`;
      }
      return;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const remaining = Math.max(0, currentRoom.expiresAt - nowSec);

    const m = Math.floor(remaining / 60);
    const s = remaining % 60;

    if (timerBadge) {
      timerBadge.textContent = `[REMAINING: ${pad(m)}:${pad(s)}]`;
    }

    if (remaining <= 0) {
      if (currentRoom.countdownTimer) {
        clearInterval(currentRoom.countdownTimer);
        currentRoom.countdownTimer = null;
      }
      showRoomDestroyed("Session expired. All messages have been permanently purged.");
    }
  };

  tick();
  currentRoom.countdownTimer = setInterval(tick, 1000);
}

async function executeRoomPoll() {
  if (!currentRoom || currentRoom.isDestroyed || currentRoom.isPolling) return;
  if (document.hidden) return; // Adaptive pause when tab backgrounded

  currentRoom.isPolling = true;
  try {
    const data = await fetchRoomMessages(currentRoom.roomId, {
      clientId: currentRoom.clientToken,
      since: currentRoom.lastMsgIndex || 0,
    });

    if (!currentRoom || currentRoom.isDestroyed) return;

    const countBadge = document.getElementById("room-count-badge");
    if (data.active_members !== undefined) {
      if (countBadge) countBadge.textContent = `[MEMBERS: ${data.active_members}/${currentRoom.maxMembers}]`;
    }

    if (data.started !== undefined && data.started !== currentRoom.started) {
      currentRoom.started = data.started;
    }

    if (data.expires_at && data.started) {
      currentRoom.expiresAt = data.expires_at;
    }

    if (!currentRoom.seenMsgIds) {
      currentRoom.seenMsgIds = new Set();
    }

    if (Array.isArray(data.messages) && data.messages.length > 0) {
      for (const msg of data.messages) {
        // Robust deduplication across all clients and poll cycles
        const msgId = msg.id || (msg.seq ? `seq_${msg.seq}` : `${msg.timestamp}_${msg.sender}_${(msg.ciphertext || "").slice(0, 32)}`);
        if (currentRoom.seenMsgIds.has(msgId)) {
          continue;
        }
        currentRoom.seenMsgIds.add(msgId);

        try {
          const decryptedPayload = await decrypt(currentRoom.cryptoKey, msg.ciphertext);
          let parsed;
          try {
            parsed = JSON.parse(decryptedPayload);
          } catch {
            parsed = { sender: msg.sender || "Peer", text: decryptedPayload, isHost: false, guestIndex: 1 };
          }

          if (parsed.sender) {
            memberColorMap.set(parsed.sender, {
              isHost: !!parsed.isHost,
              guestIndex: (parsed.guestIndex !== undefined) ? parsed.guestIndex : (parsed.isHost ? 0 : undefined),
            });
          }

          if (parsed.type === "join") {
            const roleLabel = parsed.isHost ? "HOST" : "GUEST";
            appendSystemMessage(`user joined session: ${parsed.sender} [${roleLabel}]`);
          } else if (parsed.type === "leave") {
            const roleLabel = parsed.isHost ? "HOST" : "GUEST";
            appendSystemMessage(`user left session: ${parsed.sender} [${roleLabel}]`);
          } else {
            appendChatMessage(parsed.sender || msg.sender || "Peer", parsed.text || "", msg.timestamp, parsed.isHost, parsed.guestIndex);
          }
        } catch (decErr) {
          console.warn("Failed to decrypt room message:", decErr);
        }
      }
    }

    // Monotonic sequence tracking: ensures no messages are missed even with high volume
    if (data.current_seq !== undefined) {
      currentRoom.lastMsgIndex = Math.max(currentRoom.lastMsgIndex || 0, data.current_seq);
    } else if (data.total !== undefined) {
      currentRoom.lastMsgIndex = Math.max(currentRoom.lastMsgIndex || 0, data.total);
    }
  } catch (err) {
    if (err.status === 404 || (err.message && err.message.includes("404"))) {
      showRoomDestroyed("This Flash Room was destroyed by the host or expired. All messages permanently purged.");
      return;
    }
    console.warn("Room poll error:", err);
  } finally {
    if (currentRoom) currentRoom.isPolling = false;
  }
}

function startRoomPolling() {
  if (!currentRoom) return;
  if (currentRoom.pollTimer) clearInterval(currentRoom.pollTimer);

  executeRoomPoll();
  currentRoom.pollTimer = setInterval(executeRoomPoll, 2000);
}

async function startRoomSession() {
  if (!currentRoom || currentRoom.isDestroyed) return;

  currentRoom.inSession = true;
  currentRoom.lastMsgIndex = 0; // Always start clean from index 0 to fetch all session messages
  currentRoom.seenMsgIds = new Set();

  // Update browser URL so refresh doesn't lose the room session
  if (currentRoom.roomUrl) {
    try {
      window.history.replaceState(null, "", currentRoom.roomUrl);
    } catch (e) {
      console.warn("history.replaceState error:", e);
    }
  }

  showPanel("room-chat");
  const joinView = document.getElementById("room-join-interstitial");
  const activeView = document.getElementById("room-chat-active");
  const destroyedView = document.getElementById("room-destroyed-screen");

  if (joinView) joinView.style.display = "none";
  if (destroyedView) destroyedView.style.display = "none";
  if (activeView) activeView.style.display = "block";

  // If host is entering, activate the room timer now!
  if (currentRoom.isHost && currentRoom.adminToken && !currentRoom.started) {
    try {
      const startRes = await startRoom(currentRoom.roomId, currentRoom.adminToken);
      if (startRes && startRes.expires_at) {
        currentRoom.expiresAt = startRes.expires_at;
        currentRoom.started = true;
      }
    } catch (err) {
      console.warn("Failed to activate room timer:", err);
    }
  }

  const idBadge = document.getElementById("room-id-badge");
  const countBadge = document.getElementById("room-count-badge");
  const roleBadge = document.getElementById("room-role-badge");
  const destroyBtn = document.getElementById("room-destroy-btn");
  const leaveBtn = document.getElementById("room-leave-btn");
  const titleText = document.getElementById("kali-title-text");
  const inputPrompt = document.getElementById("kali-input-prompt");
  const promptArrow = document.querySelector(".kali-prompt-arrow");

  // Register self in memberColorMap
  memberColorMap.set(currentRoom.myAlias, { isHost: currentRoom.isHost, guestIndex: currentRoom.guestIndex });

  const myColorClass = getMemberColorClass(currentRoom.myAlias, currentRoom.isHost, currentRoom.guestIndex);
  const cleanAlias = (currentRoom.myAlias || (currentRoom.isHost ? "host" : "guest")).replace(/[^a-zA-Z0-9_-]/g, "");
  if (titleText) titleText.textContent = `${cleanAlias}@flash: ~/room/${currentRoom.roomId.slice(0, 6)}`;
  if (inputPrompt) {
    inputPrompt.textContent = `┌──(${cleanAlias}㉿${currentRoom.isHost ? "host" : "peer"})-[~/room]`;
    inputPrompt.className = `kali-prompt-line ${myColorClass}`;
  }
  if (promptArrow) {
    promptArrow.className = `kali-prompt-arrow ${myColorClass}`;
  }

  if (idBadge) idBadge.textContent = `[ROOM: ${currentRoom.roomId.slice(0, 6)}]`;
  if (countBadge) countBadge.textContent = `[MEMBERS: 1/${currentRoom.maxMembers}]`;
  if (roleBadge) roleBadge.textContent = currentRoom.isHost ? "[HOST]" : "[GUEST]";

  if (destroyBtn) destroyBtn.style.display = currentRoom.isHost ? "inline-block" : "none";
  if (leaveBtn) leaveBtn.style.display = "inline-block"; // Available to both host and guest

  const msgContainer = document.getElementById("room-messages-container");
  if (msgContainer) msgContainer.replaceChildren();

  // Broadcast encrypted join announcement to room stream
  try {
    const joinPayload = JSON.stringify({
      type: "join",
      sender: currentRoom.myAlias,
      isHost: currentRoom.isHost,
      guestIndex: currentRoom.guestIndex,
    });
    const cipherJoin = await encrypt(currentRoom.cryptoKey, joinPayload);
    await sendRoomMessage(currentRoom.roomId, {
      clientId: currentRoom.clientToken,
      sender: currentRoom.myAlias,
      ciphertext: cipherJoin,
    });
  } catch (noticeErr) {
    console.warn("Failed to broadcast join notice:", noticeErr);
  }

  startRoomCountdown();
  startRoomPolling();
}

async function sendCurrentRoomMessage() {
  if (!currentRoom || currentRoom.isDestroyed) return;

  const inputEl = document.getElementById("room-message-input");
  const sendBtn = document.getElementById("room-send-btn");
  if (!inputEl) return;

  const text = inputEl.value.trim();
  if (!text) return;

  inputEl.value = "";
  inputEl.style.height = "auto";
  if (sendBtn) sendBtn.disabled = true;

  try {
    const payload = JSON.stringify({
      sender: currentRoom.myAlias,
      text,
      isHost: currentRoom.isHost,
      guestIndex: currentRoom.guestIndex,
    });
    const ciphertext = await encrypt(currentRoom.cryptoKey, payload);

    await sendRoomMessage(currentRoom.roomId, {
      clientId: currentRoom.clientToken,
      sender: currentRoom.myAlias,
      ciphertext,
    });

    executeRoomPoll();
  } catch (err) {
    if (err.status === 404 || (err.message && err.message.includes("404"))) {
      showRoomDestroyed();
    } else {
      toast(err.message || "Failed to send message", "error");
    }
  } finally {
    if (sendBtn) sendBtn.disabled = false;
    inputEl.focus();
  }
}

async function destroyCurrentRoom() {
  if (!currentRoom) return;

  const confirmed = await showConfirmModal({
    title: "Destroy Flash Room",
    tag: "[ ROOM PURGE ]",
    message: "Are you sure you want to destroy this Flash Room? All participants will be disconnected and all memory wiped immediately.",
    confirmText: "Destroy Room",
    cancelText: "Cancel",
    danger: true,
  });
  if (!confirmed) return;

  const roomId = currentRoom.roomId;
  const adminToken = currentRoom.adminToken;

  sessionStorage.removeItem(`onceflash_room_host_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_admin_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_alias_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_key_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_url_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_dur_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_max_${roomId}`);

  showRoomDestroyed("You destroyed the Flash Room. All data permanently wiped.");

  if (roomId && adminToken) {
    try {
      await destroyRoom(roomId, adminToken);
    } catch (err) {
      console.warn("Destroy room error:", err);
    }
  }
}

// ─── Flash Room DOM Event Bindings ──────────────────────────────────────────

const createRoomBtn              = document.getElementById("create-room-btn");
const roomDurationSelect         = document.getElementById("room-duration-select");
const roomMembersSelect          = document.getElementById("room-members-select");
const roomAliasInput             = document.getElementById("room-alias-input");
const roomEnablePasswordCheckbox = document.getElementById("room-enable-password");
const roomPasswordContainer      = document.getElementById("room-password-container");
const roomPasswordInput          = document.getElementById("room-password-input");

if (roomEnablePasswordCheckbox && roomPasswordContainer) {
  roomEnablePasswordCheckbox.addEventListener("change", () => {
    if (roomEnablePasswordCheckbox.checked) {
      roomPasswordContainer.style.display = "block";
      if (roomPasswordInput) roomPasswordInput.focus();
    } else {
      roomPasswordContainer.style.display = "none";
      if (roomPasswordInput) roomPasswordInput.value = "";
    }
  });
}

function getRoomClientId(roomId) {
  const key = `onceflash_room_cid_${roomId}`;
  let cid = sessionStorage.getItem(key);
  if (!cid) {
    cid = "c_" + Math.random().toString(36).slice(2, 12);
    sessionStorage.setItem(key, cid);
  }
  return cid;
}

if (createRoomBtn) {
  createRoomBtn.addEventListener("click", async () => {
    const duration = parseInt(roomDurationSelect?.value || "900", 10);
    const maxMembers = parseInt(roomMembersSelect?.value || "4", 10);
    const alias = roomAliasInput?.value.trim() || "Host";
    const isPasswordEnabled = !!(roomEnablePasswordCheckbox && roomEnablePasswordCheckbox.checked);
    const roomPassword = isPasswordEnabled ? (roomPasswordInput?.value || "").trim() : "";

    if (isPasswordEnabled && !roomPassword) {
      toast("Please enter a room password or uncheck the box", "warning");
      if (roomPasswordInput) roomPasswordInput.focus();
      return;
    }

    createRoomBtn.disabled = true;
    createRoomBtn.textContent = "[ INITIALIZING ROOM... ]";

    try {
      const cryptoKey = await generateKey();
      const keyB64 = await exportKey(cryptoKey);

      const clientToken = "c_" + Math.random().toString(36).slice(2, 12);
      const res = await createRoom({ durationSeconds: duration, maxMembers, clientId: clientToken });

      sessionStorage.setItem(`onceflash_room_cid_${res.room_id}`, res.client_id || clientToken);

      let roomUrl;
      if (isPasswordEnabled && roomPassword) {
        const passphraseMeta = await wrapKeyWithPassphrase(cryptoKey, roomPassword);
        roomUrl = buildRoomUrl(res.room_id, null, passphraseMeta);
      } else {
        roomUrl = buildRoomUrl(res.room_id, keyB64);
      }

      // Save Host credentials in sessionStorage so refresh preserves Host state seamlessly
      sessionStorage.setItem(`onceflash_room_host_${res.room_id}`, "true");
      sessionStorage.setItem(`onceflash_room_admin_${res.room_id}`, res.admin_token);
      sessionStorage.setItem(`onceflash_room_alias_${res.room_id}`, alias);
      sessionStorage.setItem(`onceflash_room_key_${res.room_id}`, keyB64);
      sessionStorage.setItem(`onceflash_room_url_${res.room_id}`, roomUrl);
      sessionStorage.setItem(`onceflash_room_dur_${res.room_id}`, String(duration));
      sessionStorage.setItem(`onceflash_room_max_${res.room_id}`, String(maxMembers));

      currentRoom = {
        roomId: res.room_id,
        keyB64,
        cryptoKey,
        adminToken: res.admin_token,
        clientToken: res.client_id || clientToken,
        myAlias: alias,
        isHost: true,
        guestIndex: 0,
        durationSeconds: duration,
        started: false,
        expiresAt: 0,
        maxMembers: res.max_members,
        lastMsgIndex: 0,
        seenMsgIds: new Set(),
        isPolling: false,
        inSession: false,
        pollTimer: null,
        countdownTimer: null,
        isDestroyed: false,
        roomUrl,
      };

      const roomShareUrlInput = document.getElementById("room-share-url");
      const roomShareDuration = document.getElementById("room-share-duration");
      const roomShareCapacity = document.getElementById("room-share-capacity");
      const roomShareProtection = document.getElementById("room-share-protection");
      const roomQrContainer   = document.getElementById("room-qr-container");

      if (roomShareUrlInput) roomShareUrlInput.value = roomUrl;
      if (roomShareDuration) roomShareDuration.textContent = `${Math.round(duration / 60)} minutes`;
      if (roomShareCapacity) roomShareCapacity.textContent = `${res.max_members} participants`;
      if (roomShareProtection) roomShareProtection.textContent = (isPasswordEnabled && roomPassword) ? "Password Protected" : "None";
      if (roomQrContainer) roomQrContainer.style.display = "none";

      if (roomPasswordInput) roomPasswordInput.value = "";
      if (roomEnablePasswordCheckbox) roomEnablePasswordCheckbox.checked = false;
      if (roomPasswordContainer) roomPasswordContainer.style.display = "none";

      showPanel("room-share");
      toast("Flash Room created successfully.", "success");
    } catch (err) {
      toast(err.message || "Failed to create Flash Room", "error");
    } finally {
      createRoomBtn.disabled = false;
      createRoomBtn.textContent = "[ CREATE FLASH ROOM ]";
    }
  });
}

const copyRoomUrlBtn = document.getElementById("copy-room-url-btn");
if (copyRoomUrlBtn) {
  copyRoomUrlBtn.addEventListener("click", async () => {
    const input = document.getElementById("room-share-url");
    if (!input || !input.value) return;
    try {
      await navigator.clipboard.writeText(input.value);
      copyRoomUrlBtn.textContent = "Copied!";
      toast("Flash Room link copied to clipboard", "success");
      setTimeout(() => { copyRoomUrlBtn.textContent = "Copy Link"; }, 2000);
    } catch {
      input.select();
      document.execCommand("copy");
      toast("Link copied to clipboard", "success");
    }
  });
}

const toggleRoomQrBtn = document.getElementById("toggle-room-qr-btn");
const roomQrContainer = document.getElementById("room-qr-container");
const roomQrMount     = document.getElementById("room-qr-mount");
if (toggleRoomQrBtn && roomQrContainer && roomQrMount) {
  toggleRoomQrBtn.addEventListener("click", () => {
    if (roomQrContainer.style.display === "block") {
      roomQrContainer.style.display = "none";
      toggleRoomQrBtn.textContent = "Show QR Code";
      return;
    }
    const input = document.getElementById("room-share-url");
    if (!input || !input.value) return;

    if (window.QRCodeGenerator && typeof window.QRCodeGenerator.generateSVG === "function") {
      try {
        const svgMarkup = window.QRCodeGenerator.generateSVG(input.value, 4);
        const parser = new DOMParser();
        const svgDoc = parser.parseFromString(svgMarkup, "image/svg+xml");
        roomQrMount.replaceChildren(svgDoc.documentElement);
        roomQrContainer.style.display = "block";
        toggleRoomQrBtn.textContent = "Hide QR Code";
      } catch (err) {
        toast("Failed to render QR Code locally", "error");
      }
    }
  });
}

const enterRoomBtn        = document.getElementById("enter-room-btn");
const shareDestroyRoomBtn = document.getElementById("share-destroy-room-btn");
if (enterRoomBtn) enterRoomBtn.addEventListener("click", startRoomSession);
if (shareDestroyRoomBtn) shareDestroyRoomBtn.addEventListener("click", destroyCurrentRoom);

const roomDestroyBtn = document.getElementById("room-destroy-btn");
const roomLeaveBtn   = document.getElementById("room-leave-btn");

async function leaveCurrentRoom() {
  if (!currentRoom) return;
  const roomId = currentRoom.roomId;
  try {
    const leavePayload = JSON.stringify({
      type: "leave",
      sender: currentRoom.myAlias,
      isHost: currentRoom.isHost,
      guestIndex: currentRoom.guestIndex,
    });
    const cipherLeave = await encrypt(currentRoom.cryptoKey, leavePayload);
    await sendRoomMessage(roomId, {
      clientId: currentRoom.clientToken,
      sender: currentRoom.myAlias,
      ciphertext: cipherLeave,
    });
  } catch (e) {
    console.warn("Leave broadcast error:", e);
  }

  sessionStorage.removeItem(`onceflash_room_host_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_admin_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_alias_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_key_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_url_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_dur_${roomId}`);
  sessionStorage.removeItem(`onceflash_room_max_${roomId}`);

  showRoomDestroyed("You left the Flash Room.");
}

if (roomDestroyBtn) roomDestroyBtn.addEventListener("click", destroyCurrentRoom);
if (roomLeaveBtn)   roomLeaveBtn.addEventListener("click", leaveCurrentRoom);

const roomSendBtn      = document.getElementById("room-send-btn");
const roomMessageInput = document.getElementById("room-message-input");

if (roomSendBtn) roomSendBtn.addEventListener("click", sendCurrentRoomMessage);

if (roomMessageInput) {
  roomMessageInput.addEventListener("keydown", (e) => {
    // On mobile / touch devices, virtual keyboards lack Shift modifier.
    // Allow Enter key to naturally insert a newline (words go down) and auto-expand,
    // while sending is performed via the dedicated [ SEND ] button.
    const isTouchOrMobile = window.matchMedia("(max-width: 768px)").matches || ("ontouchstart" in window) || (navigator.maxTouchPoints > 0);
    if (!isTouchOrMobile && e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendCurrentRoomMessage();
    }
  });

  roomMessageInput.addEventListener("input", () => {
    roomMessageInput.style.height = "auto";
    roomMessageInput.style.height = Math.min(roomMessageInput.scrollHeight, 120) + "px";
  });
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && currentRoom && !currentRoom.isDestroyed && currentRoom.inSession) {
    startRoomPolling();
  }
});

window.addEventListener("beforeunload", () => {
  if (currentRoom) {
    purgeRoomMemory();
  }
});

// ─── Guest Room Page Initialization ──────────────────────────────────────────

async function initRoomPage() {
  const parsed = parseRoomHash();
  const roomId = parsed.roomId;

  if (!roomId || (!parsed.keyB64 && !parsed.isPassphraseProtected)) {
    showRoomDestroyed("Invalid Flash Room link. Decryption key is missing from URL fragment.");
    return;
  }

  // Check if current user is the host who refreshed this room
  const isSavedHost = sessionStorage.getItem(`onceflash_room_host_${roomId}`) === "true";
  if (isSavedHost) {
    const savedAdmin = sessionStorage.getItem(`onceflash_room_admin_${roomId}`);
    const savedAlias = sessionStorage.getItem(`onceflash_room_alias_${roomId}`) || "Host";
    const savedKeyB64 = sessionStorage.getItem(`onceflash_room_key_${roomId}`) || parsed.keyB64;
    const savedUrl = sessionStorage.getItem(`onceflash_room_url_${roomId}`) || window.location.href;
    const savedDur = parseInt(sessionStorage.getItem(`onceflash_room_dur_${roomId}`) || "900", 10);
    const savedMax = parseInt(sessionStorage.getItem(`onceflash_room_max_${roomId}`) || "4", 10);
    const clientToken = getRoomClientId(roomId);

    let cryptoKey = null;
    try {
      if (savedKeyB64) {
        cryptoKey = await importRoomKey(savedKeyB64);
      }
    } catch (kErr) {
      console.warn("Failed to import saved host key:", kErr);
    }

    if (cryptoKey && savedAdmin) {
      const info = await fetchRoomInfo(roomId).catch(() => ({}));
      currentRoom = {
        roomId,
        keyB64: savedKeyB64,
        cryptoKey,
        adminToken: savedAdmin,
        clientToken,
        myAlias: savedAlias,
        isHost: true,
        guestIndex: 0,
        durationSeconds: info.duration_seconds || savedDur,
        started: !!info.started,
        expiresAt: info.expires_at || 0,
        maxMembers: info.max_members || savedMax,
        lastMsgIndex: 0,
        seenMsgIds: new Set(),
        isPolling: false,
        inSession: false,
        pollTimer: null,
        countdownTimer: null,
        isDestroyed: false,
        roomUrl: savedUrl,
      };
      memberColorMap.set(savedAlias, { isHost: true, guestIndex: 0 });
      await startRoomSession();
      return;
    }
  }

  showPanel("room-chat");
  const joinView = document.getElementById("room-join-interstitial");
  const activeView = document.getElementById("room-chat-active");
  const destroyedView = document.getElementById("room-destroyed-screen");
  const guestPassContainer = document.getElementById("room-guest-password-container");
  const guestPassInput = document.getElementById("room-guest-password-input");

  if (activeView) activeView.style.display = "none";
  if (destroyedView) destroyedView.style.display = "none";
  if (joinView) joinView.style.display = "block";

  if (guestPassContainer) {
    guestPassContainer.style.display = parsed.isPassphraseProtected ? "block" : "none";
    if (guestPassInput) guestPassInput.value = "";
  }

  try {
    const info = await fetchRoomInfo(roomId);

    const capacityVal = document.getElementById("room-join-capacity-val");
    const expiresVal  = document.getElementById("room-join-expires-val");

    if (capacityVal) {
      capacityVal.textContent = `${info.active_members || 1} / ${info.max_members} Active`;
    }
    if (expiresVal) {
      if (!info.started) {
        expiresVal.textContent = `${Math.round((info.duration_seconds || 600) / 60)} min`;
      } else {
        const nowSec = Math.floor(Date.now() / 1000);
        const leftSec = Math.max(0, info.expires_at - nowSec);
        expiresVal.textContent = formatTtl(leftSec);
      }
    }

    const confirmJoinBtn  = document.getElementById("confirm-join-room-btn");
    const guestAliasInput = document.getElementById("room-guest-alias-input");

    const hasSavedToken = !!sessionStorage.getItem(`onceflash_room_cid_${roomId}`);
    const isRoomFull = (info.is_full || (info.total_joined !== undefined && info.total_joined >= info.max_members)) && !hasSavedToken;

    if (confirmJoinBtn) {
      const newBtn = confirmJoinBtn.cloneNode(true);
      confirmJoinBtn.parentNode.replaceChild(newBtn, confirmJoinBtn);

      if (isRoomFull) {
        newBtn.disabled = true;
        newBtn.textContent = "[ ROOM FULL ]";
        toast("This Flash Room has reached maximum capacity. Session is locked.", "warning");
      } else {
        newBtn.disabled = false;
        newBtn.textContent = "[ JOIN ROOM ]";

        const handleJoinClick = async () => {
          let cryptoKey = null;
          let keyB64 = parsed.keyB64;

          if (parsed.isPassphraseProtected) {
            const pass = (guestPassInput?.value || "").trim();
            if (!pass) {
              toast("Please enter the room password to join.", "warning");
              if (guestPassInput) guestPassInput.focus();
              return;
            }
            newBtn.disabled = true;
            newBtn.textContent = "[ UNLOCKING... ]";
            try {
              cryptoKey = await unwrapKeyWithPassphrase(parsed.wrappedKeyB64, parsed.saltB64, pass, ["encrypt", "decrypt"], true);
              try {
                keyB64 = await exportKey(cryptoKey);
              } catch (expErr) {
                console.warn("Could not re-export key:", expErr);
              }
            } catch (pwErr) {
              console.error("Room unlock error:", pwErr);
              toast("Incorrect room password. Decryption failed.", "error");
              newBtn.disabled = false;
              newBtn.textContent = "[ JOIN ROOM ]";
              if (guestPassInput) guestPassInput.focus();
              return;
            }
          } else {
            try {
              cryptoKey = await importRoomKey(parsed.keyB64);
            } catch (err) {
              showRoomDestroyed("Failed to import decryption key.");
              return;
            }
          }

          newBtn.disabled = true;
          newBtn.textContent = "[ JOINING... ]";

          const alias = guestAliasInput?.value.trim() || `Guest-${Math.random().toString(36).slice(2, 6)}`;
          const clientToken = getRoomClientId(roomId);

          try {
            const joinRes = await joinRoom(roomId, clientToken);
            const guestIndex = (joinRes.guest_index !== undefined) ? joinRes.guest_index : 1;

            currentRoom = {
              roomId,
              keyB64,
              cryptoKey,
              adminToken: null,
              clientToken,
              myAlias: alias,
              isHost: false,
              guestIndex,
              durationSeconds: joinRes.duration_seconds || info.duration_seconds || 600,
              started: !!joinRes.started,
              expiresAt: joinRes.expires_at || 0,
              maxMembers: joinRes.max_members,
              lastMsgIndex: 0,
              seenMsgIds: new Set(),
              isPolling: false,
              inSession: false,
              pollTimer: null,
              countdownTimer: null,
              isDestroyed: false,
              roomUrl: window.location.href,
            };

            memberColorMap.set(alias, { isHost: false, guestIndex });

            startRoomSession();
          } catch (joinErr) {
            if (joinErr.status === 403 || (joinErr.message && joinErr.message.includes("capacity"))) {
              newBtn.disabled = true;
              newBtn.textContent = "[ ROOM FULL ]";
              toast("Room capacity reached. Session is locked to new participants.", "error");
            } else {
              toast(joinErr.message || "Failed to join room", "error");
              newBtn.disabled = false;
              newBtn.textContent = "[ JOIN ROOM ]";
            }
          }
        };

        newBtn.addEventListener("click", handleJoinClick);

        if (guestPassInput) {
          guestPassInput.onkeydown = (e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              newBtn.click();
            }
          };
        }
        if (guestAliasInput) {
          guestAliasInput.onkeydown = (e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              newBtn.click();
            }
          };
        }
      }
    }
  } catch (err) {
    if (err.status === 404 || (err.message && err.message.includes("404"))) {
      showRoomDestroyed("This Flash Room has expired or was destroyed.");
    } else {
      showRoomDestroyed(err.message || "Unable to access Flash Room.");
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Initial Route Detection
// ─────────────────────────────────────────────────────────────────────────────

const initialPath = window.location.pathname;
if (initialPath.startsWith("/view/")) {
  initViewPage();
} else if (initialPath.startsWith("/room/")) {
  initRoomPage();
} else {
  showPanel("create");
}
