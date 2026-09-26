# ⚡ OnceFlash

> **Zero-knowledge, client-side encrypted, self-destructing notes and file sharing.**
> 
> All encryption and decryption occur strictly in your browser using **AES-256-GCM** via the Web Crypto API. The backend server receives only opaque, unreadable ciphertext blobs and **never sees plaintext, encryption keys, or original file content**.

---

## 📖 What is OnceFlash?

**OnceFlash** is a high-performance, zero-knowledge ephemeral messenger and secure file-sharing application inspired by *Cryptgeon* and *PrivNote*.

It is built for transmitting confidential credentials, passwords, private API keys, and sensitive documents that **automatically burn and self-destruct** after a specified number of views or a time-to-live (TTL) expiration.

### Core Features:
- 🔐 **Zero-Knowledge Architecture**: End-to-end client-side encryption with 256-bit AES-GCM and fresh 96-bit CSPRNG initialization vectors (`window.crypto.subtle`).
- 🔗 **RFC 3986 §3.5 Hash Fragment Privacy**: Decryption keys reside exclusively in the URL `#fragment` (`#<id>:<key>`). Browsers never transmit hash fragments over HTTP, ensuring servers and edge proxies never see or log keys.
- 🌓 **Dark & Light Mode (1-Click Icon Toggle)**: Modern, distraction-free aesthetic with an electric cyan/mint theme, complete with instant theme toggling and system preference persistence (`localStorage` + `prefers-color-scheme`).
- 📁 **Multi-File Bundling & Drag-and-Drop**: Encrypt and share multiple confidential files (up to 2 MB) in a single self-destructing envelope.
- 👁️ **Read Receipts & Status Tracking**: Creators can check whether a secret is `WAITING`, `OPENED`, or `DESTROYED` without compromising zero-knowledge guarantees via blind status tokens.
- 💣 **Atomic Burn-on-Read & Dual Destruction**: Purges secrets from server RAM immediately upon view expiration. Both sender and recipient can explicitly trigger early destruction.
- 🛡️ **Secondary Passphrase Protection**: Optional client-side passphrase layer derived with PBKDF2 (100,000 iterations) for defense-in-depth against unauthorized device access.
- ⏱️ **Configurable Screen Auto-Wipe**: Recipient view automatically wipes decrypted content from memory and screen after 30s, 1m, or 5m to protect against shoulder surfing.
- 📱 **Client-Side Offline QR Generator**: 100% in-browser SVG QR code creation with zero third-party network requests.
- ⚡ **Zero-Setup Standalone Mode**: Built-in atomic in-memory engine for instant local development without installing Redis.

---

## 🚀 Quick Start Guide

You can run OnceFlash in **two ways**:
- **Method 1: Local Development (Instant Runner — Zero setup)**
- **Method 2: Deploy to Vercel (Serverless Cloud Hosting + Upstash Redis)**

---

### Method 1: Local Standalone ⚡

Runs locally with Python 3.10+ using OnceFlash's built-in **atomic in-memory ephemeral store** (no database installation needed).

#### 1. Clone the repository
```bash
git clone https://github.com/your-username/onceflash.git
cd onceflash
```

#### 2. Run the application
```bash
python run_local.py
```
*(On Windows, macOS, or Linux, `run_local.py` automatically checks dependencies and launches the application at port 8000).*

#### 3. Open in your browser
Navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---

### Method 2: Deploy to Vercel ▲

OnceFlash is pre-configured for instant deployment on **Vercel** with serverless Python execution and Edge CDN static asset delivery.

#### Why Upstash Redis for Vercel?
Because Vercel executes on stateless, distributed serverless functions across global edge regions, secrets need to be stored in a shared low-latency store so any serverless instance can atomically read and burn them. **[Upstash Redis](https://upstash.com)** provides a free, serverless, TLS-encrypted Redis database that pairs seamlessly with Vercel.

#### Step-by-Step Vercel Deployment:

1. **Push your code to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Deploy OnceFlash to Vercel"
   git branch -M main
   git remote add origin https://github.com/your-username/onceflash.git
   git push -u origin main
   ```

2. **Import into Vercel**:
   - Go to your [Vercel Dashboard](https://vercel.com).
   - Click **"Add New..."** → **"Project"**.
   - Select your `onceflash` GitHub repository and click **Import**.

3. **Add Upstash Redis**:
   - In the Vercel dashboard for your project, go to the **Storage** tab and click **Create Database** → **Serverless Redis (Upstash)** (or sign up at [upstash.com](https://upstash.com) to create a free database).
   - Copy your Redis connection URL (format: `rediss://default:TOKEN@HOST.upstash.io:6379`).

4. **Configure Environment Variables in Vercel**:
   In your Vercel Project Settings → **Environment Variables**, add:
   - `UPSTASH_REDIS_URL`: `rediss://default:YOUR_PASSWORD@YOUR_HOST.upstash.io:6379`
   - `ALLOWED_ORIGINS`: `https://your-project-name.vercel.app`

5. **Deploy**:
   - Click **Deploy**. Vercel will build the project using [`vercel.json`](vercel.json), host static files on Edge CDN, and mount `/api/*` to the Python serverless runtime.
   - Your private, zero-knowledge messenger is live!

---

## 📁 Project Structure

```
OnceFlash/
├── api/
│   └── index.py             # Vercel serverless entrypoint for FastAPI
├── backend/
│   ├── main.py              # FastAPI core with atomic read-and-burn, Upstash/Redis & in-memory engine
│   └── requirements.txt     # Backend Python dependencies
├── frontend/
│   ├── index.html           # Main composer & secret decryption web UI
│   ├── about.html           # Dedicated About, architecture, and how-to-use page
│   ├── style.css            # Responsive design system (Dark & Light tokens, Cyan/Mint brand)
│   ├── theme.js             # Standalone theme manager (localStorage & system preference)
│   ├── app.js               # Client engine: envelopes, auto-wipe, file bundling & sanitization
│   ├── crypto.js            # Web Crypto API wrapper (AES-256-GCM, CSPRNG key & IV, PBKDF2)
│   ├── api.js               # Zero-knowledge HTTP client (keys never transmitted)
│   ├── qrcode.js            # 100% offline client-side SVG QR code generator
│   └── img/                 # Application icons and brand banners
├── public/                  # Static assets mirrored for root edge hosting
├── requirements.txt         # Root dependencies for Vercel Python runtime
├── run_local.py             # 1-click standalone local runner
├── vercel.json              # Vercel configuration (routes, edge security headers & CSP)
├── .env.example             # Configuration template
├── .gitignore               # Standard git ignore rules
└── README.md                # Documentation & security architecture
```

---

## 🛡️ Security Architecture & Compliance

OnceFlash is engineered under **SSDev (Secure Software Development)** and aligned with **NIST SP 800-218 (SSDF)** and the **OWASP Top 10**:

| OWASP Top 10 | Security Control & Implementation |
|---|---|
| **A01: Broken Access Control & Path Traversal** | **Path Traversal Sanitization**: All uploaded filenames are sanitized client-side using `sanitizeFilename()` in `app.js` to strip directory traversal (`../`, `..\`), null bytes (`\0`), and shell meta-characters. |
| **A02: Cryptographic Failures** | **Web Crypto API Standard**: Uses unbroken AES-256-GCM with fresh 96-bit CSPRNG IVs per message. No custom or broken crypto. Keys are stored only in the URL `#fragment`. |
| **A03: Injection & Stored XSS** | **Strict Text & MIME Handling**: Decrypted text is rendered strictly via `textContent` (never `innerHTML`). SVG files (`image/svg+xml`) are never rendered inline to prevent script injection. Pydantic v2 schemas strictly validate all API parameters. |
| **A04: Insecure Design & Race Conditions** | **Atomic Burn-on-Read**: Implemented via atomic Redis Lua scripts (`LUA_READ_AND_BURN`) and an `asyncio.Lock()` in-memory engine. Two simultaneous readers can never view a 1-view secret twice; the first reader gets the secret, the second gets a 404. |
| **A05: Security Misconfiguration** | **Hardened HTTP Headers**: Strict `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` (prevents keys leaking in Referer headers), and server version fingerprinting removal. |
| **A07: Identification & DoS Mitigation** | **Rate Limiting**: Application-level rate limiting via SlowAPI (20 creations/min, 60 reads/min) to mitigate storage exhaustion and ID brute-forcing. |

---

## ⚙️ Configuration Reference

All settings can be configured via environment variables or a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `memory://` | Connection URI. If set to `memory://`, OnceFlash uses its thread-safe in-memory store. For hosted Redis, use `rediss://...`. |
| `UPSTASH_REDIS_URL` | `None` | Optional dedicated Upstash Redis connection string (e.g. `rediss://default:...@...upstash.io:6379`). |
| `ALLOWED_ORIGINS` | `*` | CORS origins. Restrict to `https://your-domain.vercel.app` in production. |
| `RATE_LIMIT_CREATE` | `20/minute` | Maximum notes/files that can be created per minute per IP. |
| `RATE_LIMIT_READ` | `60/minute` | Maximum retrieval attempts per minute per IP. |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

---

## 🔒 Production Hosting Checklist

When deploying to Vercel:
1. **Set Upstash Redis**: Add `UPSTASH_REDIS_URL` in Vercel Environment Variables so secrets persist across serverless instances and self-destruct atomically.
2. **Configure CORS**: Set `ALLOWED_ORIGINS=https://your-app.vercel.app` to restrict API access.
3. **Verify Edge Headers**: Vercel automatically serves the security headers defined in [`vercel.json`](vercel.json) (`CSP`, `HSTS`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`).
4. **HTTPS Enforced**: Vercel automatically provisions and renews SSL/TLS certificates with modern encryption.

---

## 📄 License

OnceFlash © 2026 | Zero-Knowledge Encrypted Messenger &bull; Burn-on-Read  
Licensed under the [GNU General Public License v3.0 (GPLv3)](LICENSE). Free and open-source forever.
