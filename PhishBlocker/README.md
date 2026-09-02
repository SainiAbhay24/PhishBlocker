# PhishBlocker
### Cyber Threat Detection, Prevention & Incident Correlation Platform
*(formerly "SentinelForge" — renamed per project owner's request)*

A defensive cybersecurity prototype: analyzes URLs before navigation, scores
risk from multiple heuristic signals, warns/blocks high-risk destinations,
and correlates browser + endpoint telemetry into incidents.

> **Scope note:** This prototype only analyzes strings/patterns and simulated
> local telemetry. It never fetches, exploits, or interacts with a suspicious
> destination, and the endpoint agent only emits synthetic events. This is a
> defensive tool, matching Section 19 ("Scope & Safety") of the original
> project roadmap.

---

## 1. Tech Stack (from the roadmap, Phase 1 & 2 built here)

| Layer              | Technology                | Purpose                                      | Status in this prototype |
|---------------------|---------------------------|-----------------------------------------------|---------------------------|
| Backend             | Python + FastAPI          | API, URL normalization, orchestration          | ✅ Built |
| Detection           | Python                    | Rules, scoring, correlation                     | ✅ Built |
| Browser             | JavaScript (Manifest V3)  | URL / navigation protection                     | ✅ Built |
| Endpoint            | Go                        | PC security telemetry collector (synthetic)     | ✅ Built |
| Database            | SQLite → PostgreSQL       | Events, detections, incidents                   | ⏳ In-memory stub for now |
| Dashboard           | React + TypeScript        | SOC analyst interface                           | ⏳ Not yet built (Phase 8) |
| Graph               | Neo4j + Cypher            | Attack-path investigation                       | ⏳ Not yet built (Phase 9/13) |
| Rules               | Sigma + YAML              | Portable detection logic                        | ⏳ Not yet built |
| File detection       | YARA                      | Authorized pattern-based analysis               | ⏳ Not yet built |
| ML                  | Python + scikit-learn     | Optional anomaly scoring                        | ⏳ Optional / Phase 7 |
| Mobile              | Android + Kotlin          | Supported mobile protection workflows           | ⏳ Not yet built (Phase 4) |

This prototype implements **Phase 1 (URL Risk Engine)**, **Phase 2 (Browser
Protection)**, and a stub of **Phase 3 (Endpoint Telemetry)** + a minimal
**Phase 9 (Correlation)** trigger, so you have a working end-to-end demo
loop: *URL → risk score → warning/block → telemetry → correlated incident*.

---

## 2. Project Structure

```
PhishBlocker/
├── README.md
├── backend/                     # Phase 1 — URL Risk Engine + API
│   ├── main.py                  # FastAPI app: /analyze, /telemetry, /incidents
│   ├── risk_engine.py           # Core scoring heuristics
│   ├── models.py                # Pydantic request/response models
│   └── requirements.txt
├── browser-extension/           # Phase 2 — Browser Protection
│   ├── manifest.json            # Manifest V3 config
│   ├── background.js            # Intercepts navigation, calls backend
│   ├── warning.html             # Block/warning page shown to the user
│   ├── warning.js               # Renders risk details on the warning page
│   ├── popup.html               # Toolbar popup
│   └── popup.js
└── endpoint-agent/              # Phase 3 — PC Telemetry (synthetic)
    ├── main.go                  # Sends a synthetic suspicious event chain
    └── go.mod
```

---

## 3. Setup Instructions

### 3.1 Backend (Python + FastAPI)

Requires Python 3.10+.

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Verify it's running:

```bash
curl http://localhost:8000/health
```

Test the risk engine directly:

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-account-locked.xn--80ak6aa92e.com/confirm-identity"}'
```

Interactive API docs are auto-generated at: `http://localhost:8000/docs`

### 3.2 Browser Extension (Chrome / Edge)

1. Make sure the backend (step 3.1) is running on `localhost:8000`.
2. Open `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the `browser-extension/` folder.
5. Visit any `http://` or `https://` URL — PhishBlocker will silently
   analyze it in the background. If it scores WARN or BLOCK, you'll be
   redirected to the local warning page before the destination loads.

   > Note: `manifest.json` ships without an `icon.png`. Chrome will still
   > load the extension fine without one; add a 128x128 PNG at
   > `browser-extension/icon.png` if you want a toolbar icon.

### 3.3 Endpoint Agent (Go)

Requires Go 1.21+.

```bash
cd endpoint-agent
go run main.go              # uses default device ID "LAB-PC-01"
# or:
go run main.go MY-LAPTOP-02 # custom device ID
```

This sends 4 synthetic telemetry events (document → PowerShell →
credential-access → lateral-movement) to the backend's `/telemetry`
endpoint, one per second.

### 3.4 Full Demo Flow

1. Start the backend (3.1).
2. Load the extension (3.2).
3. In one terminal, run the endpoint agent (3.3) — this alone won't create
   an incident yet, since correlation needs **both** a recent BLOCK-level
   URL verdict *and* recent high-severity telemetry.
4. In your browser, navigate to a synthetic malicious-looking test URL,
   e.g.: `http://paypal-account-locked.xn--80ak6aa92e.com/confirm-identity`
   (this domain does not resolve to anything real — it's for scoring only,
   your browser will show the PhishBlocker warning page before any DNS
   lookup completes if intercepted, or fail to resolve harmlessly).
5. Check `http://localhost:8000/incidents` — after both a BLOCK verdict and
   a HIGH/CRITICAL telemetry event have landed, you'll see a correlated
   `"Potential Multi-Stage Compromise Detected"` incident.

---

## 4. Roadmap Alignment

| Phase | Module | Status |
|---|---|---|
| 1 | URL Risk Engine | ✅ Done |
| 2 | FastAPI backend + event API | ✅ Done |
| 3 | SQLite → Postgres | ⏳ Currently in-memory; swap `deque` stores in `main.py` for a DB layer |
| 4 | Browser extension | ✅ Done |
| 5 | Real-time notifications | ⏳ Warning page done; push notifications not yet built |
| 6 | Go PC telemetry agent | ✅ Synthetic version done |
| 7 | Event correlation + incident creation | ✅ Minimal version done in `_maybe_correlate()` |
| 8 | Neo4j + Cypher attack graph | ⏳ Not started |
| 9 | React/TypeScript SOC dashboard | ⏳ Not started |
| 10 | Android/Kotlin mobile | ⏳ Not started |
| 11 | Threat-intel enrichment | ⏳ Not started |
| 12 | ML anomaly detection | ⏳ Optional |
| 13 | Testing, report, viva | ⏳ Up to you — code above is viva-ready and documented |

### Suggested next build steps
- Swap the in-memory `deque` stores for SQLite (quick) using `sqlite3` or `SQLModel`.
- Add a React + TypeScript dashboard hitting `/log/analysis`, `/log/telemetry`, `/incidents`.
- Add Sigma-style YAML rule definitions and map each risk signal to a MITRE ATT&CK technique ID.
