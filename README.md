# Project Akatya: Ransomware-Resilient Backup & Legal Reporting System

A host-based cybersecurity platform that detects localized ransomware attacks in real time, terminates malicious processes with an automated heuristic kill-switch, secures files through an asymmetric cloud backup pipeline, and generates digitally certifiable evidence reports compliant with **Section 65B of the Indian Evidence Act, 2000 / IT Act 2000**.

---

## Architecture Overview

```
                         ┌────────────────────────────────────────┐
                         │             FASTAPI BACKEND            │
                         │  - Asymmetric Key Gen (RSA-2048)       │
                         │  - Decryption Engine (Private Key)     │
                         │  - Section 65B PDF Generator           │
                         └───────▲───────────────────────┬────────┘
                                 │                       │
         Registration / Backups  │                       │ Secure SQL /
         Alerts / Recoveries     │                       │ Cloud Blobs
                                 ▼                       ▼
       ┌───────────────────────────┐         ┌───────────────────────────┐
       │       ENDPOINT AGENT      │         │      SUPABASE CLOUD       │
       │  - Watchdog (Sandbox)     │         │  - PostgreSQL Tables      │
       │  - Hybrid AES + RSA Enc   │         │  - Storage: akatya-backups│
       │  - Heuristic Kill-Switch  │         │  - Append-Only Versions   │
       │  - psutil Process Killer  │         └───────────▲───────────────┘
       └───────────────────────────┘                     │
                                                         │
                                             ┌───────────┴───────────────┐
                                             │    STREAMLIT DASHBOARD    │
                                             │  - Real-Time Attack Alert │
                                             │  - 65B Evidence Download  │
                                             │  - 1-Click Clean Restore  │
                                             └───────────────────────────┘
```

---

## Directory Structure

```text
Project_Akatya/
├── models/                     # Pydantic Request & Response Schemas
│   ├── endpoint.py             # RegisterRequest, EndpointResponse
│   ├── backup.py               # BackupRequest, BackupResponse
│   └── incident.py             # IncidentReportRequest, EvidenceItem
│
├── routers/                    # Modular FastAPI Route Handlers
│   ├── endpoints.py            # /api/register, /api/endpoints
│   ├── backups.py              # /api/backup, /api/backups/{endpoint_id}
│   ├── incidents.py            # /api/incident, /api/incidents, /api/incidents/{id}/report
│   └── recovery.py             # /api/recover/{endpoint_id} (Cloud Decryption Engine)
│
├── utils/                      # Core Utility Modules
│   ├── db.py                   # Supabase connection & get_db_cursor() manager
│   ├── crypto.py               # RSA-2048, AES-256-GCM, RSA-OAEP & SHA-256
│   ├── storage.py              # Supabase Object Storage API (akatya-backups)
│   └── report.py               # Section 65B Deterministic PDF Generator
│
├── server.py                   # FastAPI Application Entry Point
├── agent.py                    # Endpoint Monitoring Agent & Kill-Switch
├── simulate_attack.py          # Controlled Ransomware Simulation Script
├── dashboard.py                # Streamlit Web Monitoring & Recovery Dashboard
├── requirements.txt            # Python Dependencies
├── agent_config.json           # Cached Endpoint Credentials (Public Key only)
├── demo_sandbox/               # Monitored Folder for live testing
└── supabase/
    └── tables.sql              # PostgreSQL DDL Schemas
```

---

## Prerequisites & Installation

1. **Activate Virtual Environment:**
   ```bash
   source venv/bin/activate
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify Environment Variables (`.env`):**
   ```env
   user="postgres.<project_ref>"
   password="<db_password>"
   host="aws-1-ap-southeast-2.pooler.supabase.com"
   port="6543"
   dbname="postgres"
   secret_key="<supabase_secret_key>"
   ```

---

## Step-by-Step Demo Execution

### Terminal 1: Start Backend API
```bash
./venv/bin/uvicorn server:app --host 127.0.0.1 --port 8000 --reload
```

### Terminal 2: Start Streamlit Dashboard
```bash
./venv/bin/streamlit run dashboard.py
```
*Open `http://localhost:8501` in your browser.*

### Terminal 3: Start Endpoint Monitoring Agent
```bash
./venv/bin/python agent.py
```
*The agent registers with the backend, caches the RSA public key, seeds test files in `./demo_sandbox`, and synchronizes clean backups to Supabase Cloud Storage.*

### Terminal 4: Launch Ransomware Attack
```bash
./venv/bin/python simulate_attack.py
```
*Within <0.3s, the agent detects the rapid modification burst, invokes `psutil` to terminate the ransomware script with `SIGKILL`, freezes the backup queue, and transmits digital evidence hashes to Supabase.*

---

## Disaster Recovery & Legal Evidence

1. **Review Alert on Dashboard (`http://localhost:8501`):**
   * Red warning banner appears showing the attacked hostname, timestamp, and process termination confirmation.
2. **Download Digital Evidence Report:**
   * Click **"Download Section 65B PDF"** to get the formal certificate containing clean vs. corrupted SHA-256 hash comparisons.
3. **Execute One-Click Recovery:**
   * Navigate to the **"Disaster Recovery"** tab and click **"Initiate Cloud Recovery & Decrypt Files"**.
   * FastAPI retrieves clean backups from Supabase Storage (`akatya-backups`), decrypts AES keys using the hidden RSA Private Key, and restores uncorrupted files directly back into `./demo_sandbox`.

---

## Key Academic & Viva Talking Points

1. **Zero-Trust Asymmetric Vault:**
   * The private key is never transferred to or stored on the endpoint agent. If ransomware gains full administrator privileges on the endpoint, it cannot decrypt past snapshots or compromise historical backups.
2. **Append-Only Cloud Storage:**
   * Files in Supabase Object Storage use incremental versions ($v1, v2, v3$). Ransomware cannot overwrite prior clean states.
3. **Deterministic Forensic Compliance (Section 65B):**
   * Digital evidence reports are generated strictly via programmatic PDF templating (`fpdf2`) without LLMs/AI to maintain absolute legal admissibility under Section 65B of the Indian Evidence Act, 2000.
4. **Corrupted Hash Exclusion:**
   * During recovery, the query automatically excludes any backup version whose hash matches records in `incident_evidence`, guaranteeing that only verified pre-attack states are restored.

