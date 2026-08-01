# 🛡️ Qubit-Guard Platform Deployment Guide

Follow these steps to deploy and run the **Qubit-Guard PQC Platform** on a new system for the **PNB Hackathon 2026**.

## 1. Prerequisites
- **Python 3.9+**: For the FastAPI backend.
- **Node.js (LTS)**: For the React/Vite frontend.

## 2. Backend Setup
1.  **Extract the ZIP**: Unzip the repository to your target directory.
2.  **Navigate to Backend**: 
    ```powershell
    cd backend
    ```
3.  **Create Virtual Environment**:
    ```powershell
    python -m venv venv
    .\venv\Scripts\activate
    ```
    > Create a fresh venv on each machine. A copied `venv/` directory hardcodes the
    > absolute paths of the machine it was built on and will not run elsewhere.
4.  **Install Dependencies**:
    ```powershell
    pip install -r requirements.txt
    ```

## 3. Configuration (Critical Step) 🔑
Create or update the `backend/.env` file. `JWT_SECRET` is **mandatory** — the backend
refuses to start without it rather than fall back to a signing key committed to the
repository.

```env
PORT=5006

# REQUIRED — any long random string. Without it the server will not start.
JWT_SECRET=

# Optional — enables the AI remediation chat. Without it the chat replies
# "AI Expert Offline" and every other feature works normally.
SARVAM_API_KEY=

# Optional — enables emailed reports. Without these the report is still
# generated and downloadable, but nothing is sent.
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=YOUR_EMAIL_ADDRESS@EMAIL.com
# Gmail App Password (16 characters, no spaces)
SMTP_PASS=

# REQUIRED if the browser will access this from anywhere other than
# localhost (e.g. a bank server reached by hostname or IP from an
# evaluator's machine). Comma-separated list of the exact origin(s) the
# browser sends as `Origin` — scheme + host + port, no path. If this
# doesn't match, the browser silently blocks every API call and the app
# will look completely broken even though the backend is fine.
# Leave this line OUT (or fully delete it, don't leave it blank) to keep
# the localhost-only default: http://localhost:5173, http://127.0.0.1:5173
# Example for a server reached as http://10.20.30.40:5173 :
# CORS_ORIGINS=http://10.20.30.40:5173
```

## 4. Frontend Setup
1.  **Navigate to Frontend**:
    ```powershell
    cd ../frontend
    ```
2.  **Install Packages**:
    ```powershell
    npm install
    ```

## 5. Running the Prototype
Open two terminals to run both services simultaneously:

- **Terminal 1 (Backend)**: 
  ```powershell
  cd backend
  .\venv\Scripts\activate
  python main.py
  ```
  *(Service runs on http://localhost:5006)*

- **Terminal 2 (Frontend)**:
  ```powershell
  cd frontend
  npm run dev
  ```
  *(Dashboard accessible at http://localhost:5173)*

## 6. Default Login Credentials
- **Username**: `admin`
- **Password**: `pnb_password_2026`

Every API route except `/api/auth/*` and `/api/health` requires a valid session
token, enforced server-side.

---

## Deploying somewhere evaluators reach over the network

Steps 1–5 above assume you're browsing from the same machine the servers run on.
If evaluators will instead open a browser on a **different machine** and point it
at this server's hostname or IP, two things change:

1. **Frontend must bind beyond localhost.** By default `npm run dev` only listens
   on localhost. Run it as:
   ```powershell
   npm run dev -- --host
   ```
   and note the "Network:" URL Vite prints — that's what evaluators should open.

2. **Backend must allow that exact origin.** Set `CORS_ORIGINS` in `backend/.env`
   to the exact scheme+host+port evaluators' browsers will use (see step 3 above).
   Skipping this doesn't produce an obvious error — the app just looks broken,
   because the browser silently blocks every API call before it reaches the server.

If instead someone will RDP/log into the server itself and browse there locally,
none of this is needed — `localhost` works out of the box.

## Known environment-dependent behaviour, not bugs

A locked-down bank network may block some outbound traffic this app makes. When
that happens the app is designed to say so honestly rather than fail silently or
fake success:
- **SMTP blocked** → report says "generated but NOT sent" (see Troubleshooting).
- **Sarvam AI unreachable** → chat replies "AI Expert Offline".
- **VPN pillar (IKE ports 500/4500 UDP)** → reports `N/A` / not assessed rather
  than a fabricated score if those ports aren't routed outbound.

None of these need fixing — they're the app correctly reporting what it could
and couldn't verify on that network.

---

## Troubleshooting

**`RuntimeError: JWT_SECRET is not set`** — expected behaviour. Set `JWT_SECRET`
in `backend/.env` and restart.

**Report says "generated but NOT sent"** — SMTP is unconfigured, blocked, or timed
out. This message is accurate: no email was sent. The report itself was still
generated; use **Download PDF** to retrieve it. There is no fallback that reports a
successful send when nothing was delivered.

**A pillar shows "N/A" instead of a score** — that pillar could not be probed
(DNS failure, firewall, host down). `N/A` means *not assessed*; it is deliberately
not rendered as `0`, which would read as "no risk". Only pillars that returned real
observations contribute to the overall QVS.
