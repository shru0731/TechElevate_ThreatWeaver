# ThreatWeaver — Frontend

A production-grade cybersecurity dashboard for attack path prediction and AI-driven remediation.

---

## Folder Structure

```
threatweaver/
├── public/
│   └── index.html
├── src/
│   ├── api/
│   │   ├── threatweaverApi.ts     # Real Axios API layer
│   │   └── mockApi.ts             # Mock data for dev/demo
│   ├── app/
│   │   └── store.ts               # Redux store
│   ├── components/
│   │   ├── graph/
│   │   │   ├── NetworkGraph.tsx   # D3 force graph with zoom/pan
│   │   │   └── NodeDetail.tsx     # Node detail popup
│   │   ├── panels/
│   │   │   ├── AttackPathsPanel.tsx
│   │   │   ├── RemediationPanel.tsx
│   │   │   ├── AlertsPanel.tsx
│   │   │   └── RightPanel.tsx     # Panel router/container
│   │   ├── sidebar/
│   │   │   ├── Sidebar.tsx
│   │   │   └── GnriGauge.tsx
│   │   ├── shared/
│   │   │   ├── StatsBar.tsx
│   │   │   ├── LoadingOverlay.tsx
│   │   │   ├── ErrorBanner.tsx
│   │   │   └── ToastContainer.tsx
│   │   └── Dashboard.tsx          # Main layout
│   ├── features/
│   │   ├── analysis/analysisSlice.ts
│   │   ├── paths/pathsSlice.ts
│   │   ├── remediation/remediationSlice.ts
│   │   └── ui/uiSlice.ts
│   ├── hooks/
│   │   └── redux.ts               # Typed useAppDispatch / useAppSelector
│   ├── styles/
│   │   └── index.css
│   ├── types/
│   │   └── index.ts               # All TypeScript types
│   ├── App.tsx
│   └── index.tsx
├── .env
├── package.json
├── tailwind.config.js
├── postcss.config.js
└── tsconfig.json
```

---

## Setup & Run

### 1. Install dependencies

```bash
cd threatweaver
npm install
```

### 2. Start the dev server

```bash
npm start
```

App will open at **http://localhost:3000**

### 3. Configure the API

Edit `.env` to point to your FastAPI backend:

```
REACT_APP_API_URL=http://localhost:8000/api/v1
```

By default the app uses **mock data** (no backend needed). To switch to real API, in each Redux slice replace:

```ts
// mockApi call:
return await mockAnalyze();

// with real API call:
return await analyzeNetwork({ ip_range: ipRange });
```

---

## Features

### Graph Panel
- D3.js force-directed network graph
- **Scroll to zoom**, **drag to pan**, **double-click to reset**
- Zoom controls: +/– buttons and reset
- Nodes colored by risk: green <30, yellow 30–60, orange 60–80, red >80
- Risk arc fill inside each node
- Click any node → detail popup (CVEs, services, OS, risk meter)
- Drag nodes to rearrange
- Arrow markers on edges with protocol labels on highlighted paths

### Sidebar
- IP range input
- **New Analysis** button — runs scan, populates graph
- **Predict Attack Paths** button — ML-based path prediction
- GNRI gauge (Global Network Risk Index) with animated arc
- Navigation tabs

### Attack Paths Panel
- Lists all predicted attack paths sorted by risk
- Shows risk score, likelihood %, node chain
- Click path → **highlights path in graph with cyan glow**
- One-click generate remediation plan

### Remediation Panel
- AI-generated steps categorized as Immediate / Short-Term / Long-Term
- Priority badge (CRITICAL / HIGH / MEDIUM / LOW)
- Step count summary

### Alerts Panel
- Groups alerts by severity
- GNRI warning banner when score ≥ 70
- Critical alerts pulse-animate
- Click alert → auto-navigate to remediation

### UX
- Live UTC clock in header
- Real-time stats bar (node count, critical nodes, etc.)
- Loading spinner with animated rings
- Toast notifications
- Error banners with dismiss
- Full dark theme with subtle grid texture

---

## Switching to Production API

In `src/features/analysis/analysisSlice.ts`:
```ts
// Remove mock:
// return await mockAnalyze();

// Uncomment real:
return await analyzeNetwork({ ip_range: ipRange });
```

Same pattern for `pathsSlice.ts` and `remediationSlice.ts`.

---

## Build for Production

```bash
npm run build
```

Output in `build/` directory — serve with any static file server.
