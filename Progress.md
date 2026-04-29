# ThreatWeaver

 **Phase 1:  Foundation & Core Backend**     

- [ ]  Setup
- Initialize project structure (backend/, frontend2/)
- Set up Python virtual environment
- Configure .env with database, JWT, and LLM settings
- Initialize Git repository with proper .gitignore
- Set up PostgreSQL connection with SQLAlchemy

- [ ]  Backend Core
- FastAPI app with lifespan events (startup/shutdown)
- CORS middleware for frontend communication
- Request ID middleware for tracing
- Exception handlers for consistent error responses
- Health check endpoints (/health,  /test-db)

- [ ]  Authentication
- User model with password hashing (passlib/bcrypt)
- JWT token generation and validation
- Refresh token flow
- Auth router (register, login, refresh, logout)
- Dependency for protected routes

**Phase 2:  Graph Engine & Attack Analysis**

- [ ]  Graph Infrastructure
- NetworkNode and NetworkEdge models
- Graph Engine with NetworkX integration
- Topology ingestion from JSON payloads
- Node risk scoring algorithm
- Edge weight calculation (CVSS, exploitability, patch factor)

- [ ]  Attack Path Engine
- Path discovery algorithm (DFS/BFS with depth limits)
- Path risk ranking and scoring
- Top-N path filtering
- Attack Path storage models
- Snapshot system for analysis history

**Frontend & Polish**

- [ ]  Frontend Setup
- React + TypeScript + Vite initialization
- Redux Toolkit store configuration
- Tailwind CSS with dark theme
- Axios API layer with mock fallback
- Feature slices (analysis, paths, remediation, ui)

- [ ]  Graph Visualization
- D3 force-directed graph component
- Zoom/pan interactions
- Node coloring by risk level
- Risk arc visualization
- Node detail popup on click
- Path highlighting with glow effect

- [ ]  Dashboard & Panels
- Main Dashboard layout
- Sidebar with GNRI gauge
- Attack Paths Panel with risk scores
- Remediation Panel with categorized steps
- Alerts Panel with severity grouping
- StatsBar with live metrics
- LoadingOverlay, ErrorBanner, ToastContainer
- Modifying frontend part,added auth pages

  **Phase 1: Backend** 

- [ ]  LLM Integration
- LLM module with Groq/Gemini/mock support
- Remediation generation service
- Fallback rule-based guidance when LLM unavailable
- RemediationPlan model and storage
- /llm/status endpoint for capability reporting
