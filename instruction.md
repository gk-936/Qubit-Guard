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
