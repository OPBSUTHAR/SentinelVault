# 🛡️ SentinelVault

**AI-powered password manager with security monitoring and breach detection.**

A zero-knowledge vault (AES-256-GCM + Argon2id), a breach monitor built on the Have I Been Pwned
k-anonymity API, password-health scoring with auto-rotation, TOTP 2FA management, secure sharing,
emergency access, and login-anomaly/phishing detection — delivered as a FastAPI backend and a
React + Vite dashboard.

The whole stack runs locally with one command and deploys to Vercel as a single serverless
function serving the built SPA.

---

## ✨ Features

| Area | What it does |
| --- | --- |
| **Password generation** | CSPRNG password & passphrase generator with policies (basic / strong / paranoid / PIN / passphrase). Every generated secret is scored before you save it. |
| **Breach detection** | "This password was found in a data breach — change it now" via the **HIBP Pwned Passwords** range API (k-anonymity: only a 5-char SHA-1 prefix ever leaves the app). Account/email lookup via the HIBP API when a key is configured, with a built-in reference catalog of famous breaches as fallback. |
| **Password health** | Per-item strength scoring (zxcvbn-style: dictionaries, keyboard walks, sequences, leetspeak, repetition) plus a vault-wide health score, reuse map, aging report and "change these now" action list. |
| **Auto-rotation** | One click rotates a single password or **all flagged accounts** to fresh 16-char secrets; vault items are re-encrypted automatically. |
| **2FA integration** | Store TOTP secrets per item, generate authenticator QR codes, and view live 6-digit codes with a countdown — RFC 6238 implemented in-house. |
| **Secure sharing** | Time-limited, view-limited share links whose encryption key is derived from the token itself — the server stores only ciphertext. |
| **Emergency access** | Trusted contacts request access; the owner (with the vault unlocked) approves and an encrypted bundle is released to the contact's tracking link. |
| **Login anomaly detection** | Every sign-in is fingerprinted (device, /16 network, hour). Alerts fire for new devices, new networks, unusual hours, brute-force bursts and "success after failures". |
| **Phishing detection** | URL analyzer for lookalike brands, suspicious TLDs, punycode, IP hosts, shorteners, lure keywords and more. |
| **Zero-knowledge crypto** | Argon2id master-key derivation, HKDF subkeys per purpose, AES-256-GCM per item with AAD binding, HMAC verifier (the password is never stored), recovery-key wrapping. |

---

## 🏗️ Architecture

```
Vault ──▶ Encryption Engine ──▶ (API) ──▶ Breach Monitor ──▶ Health Dashboard
  │            │                                          
  │            └─ Argon2id key derivation · AES-256-GCM · HKDF subkeys · TOTP (RFC 6238)
  │
  ├─ TOTP 2FA · Secure sharing · Emergency access · Auto-rotation · Login anomaly detection
```

- **Backend** — FastAPI, SQLite (WAL), python-jose JWT, argon2-cffi, cryptography.
- **Frontend** — React 18 + Vite + TypeScript, react-router, zustand, lucide-react, dark UI.
- **Serverless** — the FastAPI app becomes a single Vercel Function; the built SPA is served by the same origin, so the API base URL stays `/api`.

### Security model (short version)

1. **Master password → master key** with Argon2id (time 3, 64 MiB, parallelism 2) over a random 16-byte salt.
2. **Auth verifier** = HMAC-SHA256(master key) stored server-side — login proves key knowledge without storing the password.
3. **Per-purpose subkeys** via HKDF-SHA256 domain separation (`vault-items`, `recovery`, `emergency-bundle`, share tokens…).
4. **Every vault item** is AES-256-GCM encrypted with the item id as AAD; the server only ever sees ciphertext.
5. **Master key lives in server memory only** — sessions lock after inactivity, and a restart locks every vault.
6. **Recovery** wraps the master key under a 256-bit recovery key (base32, shown once). Changing the master password re-encrypts all items and issues a new recovery key.
7. **Share links** derive their encryption key from the random token via SHA-256 — ciphertext at rest, decryption happens per view.
8. **Emergency bundles** are encrypted under a key derived from the contact's request token and only built while the owner's vault is unlocked.

> Honest trade-offs are documented in code: emergency access keeps the request token server-side so the
> bundle can be built at approval time (a production system would use per-contact public keys).

---

## 🚀 Quick start (local)

Requirements: Python 3.12 (e.g. via `uv`), Node 18+.

```powershell
# 1. Backend
cd backend
uv venv --python 3.12 .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt   # or: uv pip install -r requirements.txt
copy .env.example .env                                        # adjust secrets if you like
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. Frontend (new terminal)
cd frontend
npm install
npm run dev        # http://localhost:5176  (proxies /api → :8000)
```

Open **http://localhost:5176**, create an account (save the recovery key!), then click
**Load demo vault** on the dashboard to populate 14 realistic accounts and watch the health
score, breach flags and rotation flow.

API reference: **http://127.0.0.1:8000/api/docs**

### Demo flow (matches the product spec)

1. Save a new password → live scorer answers *"This password is strong (92/100)"*.
2. Breach monitor → *"Your email was in a recent breach"* style checks (password & account).
3. Health dashboard → *"3 accounts using this password need changing"* (reuse map).
4. Click **Auto-rotate all** → fresh secrets generated for every flagged account.

### 🧩 Browser auto-fill extension (Chrome/Edge, MV3)

The repo ships a Manifest V3 extension in [`extension/`](./extension) that talks directly to your
own SentinelVault API — no third-party server involved.

1. Sign in to the dashboard once (so your vault has items).
2. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → pick the `extension/` folder.
3. Click the toolbar icon, confirm the API base URL (default `http://localhost:8000`), and sign in
   with the same account. The master password is used once to obtain a session token; only the token
   is stored in the browser.
4. On any login page, open the popup and hit **Fill** — the username/email and password fields are
   auto-filled (or use **Copy pw** for apps without a web form).

> The extension requests the item's decrypted value through the authenticated API at the moment you
> click Fill, so nothing is cached in the browser.

---

## 🔌 API overview (all under `/api`)

- `POST /auth/register|login|unlock|lock|change-password|recovery`, `GET /auth/me`
- `GET|POST /vault/items`, `GET|PUT|DELETE /vault/items/{id}`, `POST /vault/rotate`, `GET /vault/health`, `GET /vault/items/{id}/totp`, `POST /vault/seed-demo`
- `POST /tools/strength|generate|phishing|totp/code|totp/verify|totp/generate|totp/qr`, `GET /tools/policies`
- `POST /security/check-password|check-email`, `GET /security/events|alerts|summary`, `POST /security/alerts/{id}/read`
- `POST|GET /shares`, `DELETE /shares/{id}`, `GET /shares/view/{token}` *(public)*
- `GET|POST /emergency/contacts`, `DELETE /emergency/contacts/{id}`, `POST /emergency/request` *(public)*, `GET /emergency/check/{token}` *(public)*, `GET /emergency/requests`, `POST /emergency/requests/{id}/decide`
- `GET /dashboard` — aggregate for the home page
- `GET /api/docs` — OpenAPI UI

---

## 🧪 Verification

A full end-to-end smoke test exercises 58 checks — registration → seeded vault → health scoring →
rotation → live HIBP lookups (e.g. `password123` is found in 2,266,543 breaches) → sharing view limits →
emergency bundle release → lock/unlock → brute-force alerts → recovery reset.

---

## ☁️ Deployment

Deployed on Vercel as a single serverless FastAPI function (`index.py` entrypoint) with the React SPA
built by `vercel.json`'s build command and served from the same origin (`/api` stays relative).

Serverless notes: the SQLite database lives in `/tmp` and resets when the function cold-starts; master
keys live in memory, so every cold start begins with a locked vault — unlock (or register a fresh demo
account) to explore.

---

## 🌐 Live Demo

**https://sentinelvault-pearl.vercel.app** — deployed on Vercel as a single FastAPI serverless function that also serves the React build.

- Register a fresh account on the live site — Argon2id key derivation and AES-256-GCM encryption run fully end-to-end in the cloud.
- The demo database lives on ephemeral `/tmp` storage, so accounts reset on cold start — perfect for evaluating, not for storing real secrets.
- Sessions are in-memory by design: after a cold start the vault starts locked; unlock with your master password or the recovery key.
- Breach checks call the live HIBP k-anonymity API from the deployment (`password123` → 2,266,543 hits).
- The auto-fill extension is local-only: load it unpacked from `extension/` and point it at the live URL.

## ⚠️ Notes & limitations

- Sessions are in-memory by design (a restart locks vaults); for multi-instance deployments move the
  session store behind a shared, encrypted service.
- Live account-breach lookups require a paid HIBP API key (the password range API is free).
- HTTPS should terminate in front of the API in production.

## 📄 License

MIT — see [LICENSE](./LICENSE).
