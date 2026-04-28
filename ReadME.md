# ThreatWeaver

## AI-Powered Cyber Attack Prediction and Remediation System

## Overview

ThreatWeaver is an AI-driven cybersecurity platform that predicts likely attack paths in a network before they occur and generates remediation guidance.

Unlike traditional security systems that respond after an attack, ThreatWeaver uses graph-based modeling and generative AI to identify vulnerabilities, simulate attacker movement, and recommend preventive actions.

## Current Status

- Day 1: graph modeling, risk scoring, attack path prediction, basic remediation flow
- Day 2: PostgreSQL persistence, snapshot history, attack-path storage, retrieval APIs, LLM status endpoint
- Day 3: Alembic migrations, refresh-token auth, RBAC, request tracing, async jobs, live ingestion, and export APIs

## Key Features

- Attack graph modeling for systems, services, and trust relationships
- Risk scoring for exposed assets and vulnerable nodes
- Attack path prediction and ranking
- AI-assisted remediation guidance
- Interactive graph visualization for analysts
- Simulation-oriented architecture for future attack scenario analysis

## How It Works

1. Load network and asset data
2. Construct the attack graph with NetworkX
3. Calculate node and path risk scores
4. Predict probable attacker movement
5. Rank the most critical attack paths
6. Generate remediation guidance with an LLM
7. Visualize findings in the frontend dashboard

## Final Tech Stack

This is the locked project stack we are using for ThreatWeaver.

### Frontend

- React with Vite
- Tailwind CSS
- React Router
- `react-force-graph` for graph visualization

Optional Phase 2 polish:

- Framer Motion

### Backend

- FastAPI
- Uvicorn
- SQLAlchemy
- Pydantic
- NetworkX
- Groq or Gemini for remote remediation generation
- Rule-based fallback remediation when remote LLM is disabled or unavailable

### Database

- PostgreSQL
- `psycopg2` driver

### Authentication

- JWT-based authentication in FastAPI
- `passlib` for password hashing

### Reporting

Phase 2:

- WeasyPrint for PDF report generation

### Development and Deployment

Local development:

- Backend runs with Uvicorn
- Frontend runs with `npm run dev`

Planned deployment:

- Frontend on Vercel
- Backend on Render or Railway
- PostgreSQL on Render or Neon

## Architecture

```text
Frontend (React)
   ->
API Calls (Axios)
   ->
Backend (FastAPI)
   ->
Core Engines:
   - Graph Engine (NetworkX)
   - Risk Engine
   - Attack Path Engine
   - LLM Engine (Gemini)
   ->
PostgreSQL Database
```

## Project Direction

ThreatWeaver is being built as a graph-first cybersecurity analysis system with a simple, production-aligned architecture:

- React frontend for visualization and analyst workflows
- FastAPI backend for orchestration and APIs
- NetworkX-powered graph reasoning for attack modeling
- PostgreSQL for durable storage
- Gemini-powered LLM features for remediation and explanation

## Setup Notes

Implementation should align to the stack above unless we explicitly decide to change the architecture later.

## Repository Structure

```text
ThreatWeaver/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── repositories/
│   │   ├── schemas/
│   │   └── services/
│   ├── data/
│   ├── main.py
│   ├── requirements.txt
│   └── test_graph.py
└── ReadME.md
```

## Local Setup

### Prerequisites

- Python 3.11
- PostgreSQL running locally
- A database created for this project, for example `threatweaver`

### 1. Clone the repository

```powershell
git clone <your-repo-url>
cd ThreatWeaver
```

### 2. Create a virtual environment

```powershell
cd backend
python -m venv venv
```

If `python` points to the Windows Store alias on your machine, use your installed Python path instead.

### 3. Activate the virtual environment

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

### 5. Create `backend/.env`

Add your own local environment values. The app expects at least:

```env
DATABASE_URL=postgresql://postgres:<your-password>@localhost:5432/threatweaver
JWT_SECRET=<your-secret>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7
TASK_QUEUE_MODE=background
REDIS_URL=redis://localhost:6379/0
ENABLE_REMOTE_LLM=false
LLM_PROVIDER=groq
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_BASE_URL=https://api.groq.com/openai/v1
GEMINI_API_KEY=
```

Notes:

- Set `ENABLE_REMOTE_LLM=true` only if you want live Groq or Gemini responses.
- If remote LLM is disabled or not configured correctly, ThreatWeaver falls back to built-in remediation guidance.
- Leave `TASK_QUEUE_MODE=background` for local development.
- Switch to `TASK_QUEUE_MODE=celery` only after Redis and a Celery worker are configured.

### 6. Run database migrations

From `backend/`:

```powershell
.\venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
```

Notes:

- Alembic is now the source of truth for schema creation and upgrades.
- The backend no longer creates or patches production-like tables automatically at startup.
- To inspect the migrated schema, run:

```powershell
.\venv\Scripts\python.exe verify_schema.py
```

## Running The Backend

From `backend/`:

```powershell
.\venv\Scripts\python.exe -m uvicorn main:app --reload
```

Useful URLs:

- Swagger docs: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- Demo dashboard: `http://127.0.0.1:8000/`

## Manual Testing

### Day 1

Run the legacy graph workflow:

```powershell
.\venv\Scripts\python.exe test_graph.py
```

Expected output includes:

- all discovered paths
- best attack path
- path risk
- remediation guidance

### Day 2

Use Swagger at `http://127.0.0.1:8000/docs` or an API client.

Recommended order:

1. `GET /api/v1/health`
2. `GET /api/v1/ready`
3. `GET /api/v1/llm/status`
4. `POST /api/v1/auth/register`
5. `POST /api/v1/auth/login`
6. `POST /api/v1/analysis/analyze`
7. `GET /api/v1/analysis/snapshots/{snapshot_id}`
8. `POST /api/v1/exports`
9. `GET /api/v1/exports/{export_id}`
10. `POST /api/v1/analysis/analyze-live`
11. `GET /api/v1/jobs/{job_id}`

How to use the IDs:

- `POST /api/v1/analysis/analyze` returns a `snapshot_id`
- `POST /api/v1/exports` returns an `export_id`
- `POST /api/v1/analysis/analyze-live` returns a `job_id`
- Paste those values into the matching GET routes in Swagger

### Example Analyze Payload

```json
{
  "user_id": 2,
  "snapshot_name": "manual-test",
  "entry_node": "internet",
  "target_node": "db",
  "max_depth": 4,
  "top_n_paths": 2,
  "topology": {
    "nodes": [
      {
        "id": "internet",
        "type": "external",
        "vuln": 2.5,
        "criticality": "LOW",
        "exposure": 1.0,
        "cves": [],
        "exploit_in_wild": false
      },
      {
        "id": "app",
        "type": "server",
        "vuln": 8.2,
        "criticality": "HIGH",
        "exposure": 7.0,
        "cves": ["CVE-2024-0001"],
        "exploit_in_wild": true
      },
      {
        "id": "db",
        "type": "database",
        "vuln": 9.1,
        "criticality": "CRITICAL",
        "exposure": 4.0,
        "cves": ["CVE-2024-0002"],
        "exploit_in_wild": false
      }
    ],
    "edges": [
      {
        "source": "internet",
        "target": "app",
        "cvss": 7.5,
        "exploitability": 8.0,
        "patch_factor": 0.9,
        "lateral_movement_probability": 0.8
      },
      {
        "source": "app",
        "target": "db",
        "cvss": 8.8,
        "exploitability": 8.6,
        "patch_factor": 0.7,
        "lateral_movement_probability": 0.9
      }
    ]
  }
}
```

## Important API Endpoints

- `GET /api/v1/health`
- `GET /api/v1/ready`
- `GET /api/v1/test-db`
- `GET /api/v1/llm/status`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/analysis/predict`
- `POST /api/v1/analysis/analyze`
- `POST /api/v1/analysis/analyze-live`
- `GET /api/v1/analysis/snapshots/{snapshot_id}`
- `GET /api/v1/analysis/users/{user_id}/snapshots`
- `POST /api/v1/ingestion/jobs`
- `GET /api/v1/jobs/{job_id}`
- `POST /api/v1/jobs/remediation`
- `POST /api/v1/exports`
- `GET /api/v1/exports/{export_id}`
- `GET /api/v1/exports/{export_id}/download?token=...`
- `GET /api/v1/demo/story`
- `GET /api/v1/demo/dashboard`

## Git And Security Notes

- Never commit `backend/.env`
- Never commit `backend/venv`
- Rotate any API key that was ever exposed in screenshots, commits, or shared files
- Review `git status --short` before every commit

Safe staging example:

```powershell
git add .gitignore
git add ReadME.md
git add backend/main.py
git add backend/requirements.txt
git add backend/app
git status --short
```

Avoid `git add .` until you are confident only safe files are untracked.
