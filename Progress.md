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

  **Phase 3: Backend** 

- [ ]  LLM Integration
- LLM module with Groq/Gemini/mock support
- Remediation generation service
- Fallback rule-based guidance when LLM unavailable
- RemediationPlan model and storage

  Phase4:Frontend, Visualization & UX (Polished Version)

- [ ]  Frontend Setup
- React + TypeScript + Vite setup completion
- Redux Toolkit state management integration
- Tailwind CSS dark mode UI system
- Axios API layer with fallback/mock handling
- Feature-based architecture (analysis, paths, remediation, UI)



- [ ]  Graph Visualization and Interaction
- D3 force-directed attack graph implementation
- Zoom, pan, and node focus interactions
- Node coloring based on Node Risk Score (NRS)
- Attack path highlighting with step-by-step visualization
- Interactive node detail panel (CVE, risk, exposure info)



- [ ]  Dashboard and Monitoring UI
- Central security analytics dashboard
- Attack Path Ranking Panel (Top-N paths view)
- AI Remediation Output Panel (structured display)
- Alerts Panel with severity grouping (High/Medium/Low)
- Live system metrics widgets (latency, risk stats)



- [ ]  Advance Visualization Layer
- Attack simulation playback (step-by-step path traversal animation)
- Time-based attack graph evolution view (historical changes)
- Risk heatmap overlay on network graph
- “Explain Attack Path” AI interaction button per path/node
- Exportable SOC-style report view (PDF/JSON export)



- [ ]  Frontend Intelligence Integration
- LLM response rendering in structured UI format
- Confidence score visualization for remediation suggestions
- Human-readable attack chain explanation panel
- Real-time update sync with backend analysis results



- [ ]  UI/UX polish Layer
- Loading states for graph + LLM processing
- Error boundaries and fallback UI components
- Toast notification system for alerts
- Responsive layout for SOC-style monitoring screens
- Dark-themed cybersecurity dashboard optimization
- /llm/status endpoint for capability reporting

  
