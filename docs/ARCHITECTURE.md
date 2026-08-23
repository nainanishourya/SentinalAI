# SentinalAI — Architecture & Operator Notes

This document exists so that a future session (Claude or a human) can pick this
project back up without re-deriving how it works. It describes what was built,
why it's built that way, and exactly how the pieces are wired together.

## What this is

SentinalAI is a self-contained, real-time Security Operations Center (SOC) demo.
Synthetic attack traffic (or a real malicious file upload) is fed into a
9-agent LangGraph pipeline that detects, investigates, and reports on the
incident the way a real SOC team would — and every step streams live to a
dashboard over a WebSocket.

It is a **local full-stack app**, not a hosted Claude Artifact: a Python
FastAPI backend + LangGraph workflow, and a static HTML/CSS/JS dashboard
served by that same backend. This was a deliberate choice — the workflow
needs a real backend process (WebSocket push, SQLite persistence, an LLM
client with a real API key, a file-upload endpoint that inspects raw bytes),
none of which a browser-only Artifact can do.

## Why OpenRouter + free models

The user provided an OpenRouter API key rather than a direct Anthropic key,
so all agent reasoning goes through OpenRouter's OpenAI-compatible
`/chat/completions` endpoint (`backend/app/llm.py`). The user asked to use
**free-tier models** to avoid burning API credits. Free models on OpenRouter
share upstream rate-limit pools and occasionally return HTTP 429, so
`llm.ask_json()` tries a short ordered list of free models
(`config.OPENROUTER_FALLBACK_MODELS`, default first entry
`nvidia/nemotron-3-super-120b-a12b:free`) before giving up. If every model
fails (or no key is configured), each agent node catches the exception and
falls back to deterministic, template-based reasoning instead of crashing the
pipeline — the incident report is marked `llm_backed: false` in that case so
the dashboard is honest about which sections are real model output.

**If you want to switch models** (e.g. to a paid model for better quality),
change `OPENROUTER_MODEL` in `backend/.env` — no code changes needed.

## The multi-agent pipeline (LangGraph)

`backend/app/graph/workflow.py` builds a `langgraph.graph.StateGraph` over a
shared `SOCState` TypedDict (`backend/app/graph/state.py`). Ten nodes, run in
this fixed order for every incident:

1. **Orchestrator** (`orchestrator_agent`) — the LangGraph workflow controller
   itself, shown as its own visible pipeline step. Assigns the incident ID and
   kicks off the run. Deterministic, no LLM call.
2. **Log Ingestion Agent** — normalizes the raw synthetic log lines, counts
   sources. Deterministic (real SIEMs do this with fast rule/parsing code,
   not an LLM call, so this agent mirrors that).
3. **Detection Engine** — a keyword/heuristic rule table
   (`agents.DETECTION_RULES`) scans the ingested logs and decides
   `is_malicious` + a `detected_category`. Deterministic and fast, like a real
   detection engine. **This is also the branch point**: LangGraph's
   `add_conditional_edges` routes benign traffic straight to `END`, so only
   real detections continue into the expensive 6-agent investigation chain
   below. This is why the ambient background traffic (see below) doesn't spam
   the LLM.
4. **Incident Creation Agent** — opens the incident record (ID, severity,
   status). Deterministic.
5. **Detection Analyst Agent** — *first LLM-backed agent.* Explains, in plain
   language, *why* this looks like a real incident and lists suspicious
   patterns + a confidence score.
6. **Threat Intelligence Agent** — LLM-backed. Produces a plausible
   campaign/actor hypothesis and IOC context. **This is simulated intel, not
   a live feed** — the agent's own output includes a disclaimer sentence
   saying so, and the dashboard doesn't claim otherwise.
7. **Attack Reconstruction Agent** — LLM-backed. Takes all correlated events
   and reconstructs them into an ordered timeline / kill-chain narrative.
8. **Root Cause Analyst Agent** — LLM-backed. Identifies the underlying
   control gap that allowed the incident, not just what happened.
9. **MITRE ATT&CK Mapper Agent** — LLM-backed. Maps the incident to real
   MITRE ATT&CK Enterprise tactics/techniques. Immediately after this node,
   `scoring.score_run()` compares the model's technique IDs against the
   scenario's known ground-truth techniques to compute the **prediction
   accuracy score** shown on the dashboard (65% weight on MITRE technique
   overlap, 35% weight on category match).
10. **Incident Response Suggestion Agent** — LLM-backed. Produces a concrete
    response plan (immediate/containment/eradication/recovery/preventive).

Each node appends a `trace` entry (`{agent, message, timestamp, llm_backed}`)
to the shared state. `backend/app/pipeline.py::run_pipeline()` drives the
graph with `GRAPH.astream(...)`, and after **every single node**, broadcasts
an `agent_step` WebSocket message with that node's trace entry and a public
state snapshot — this is what makes the dashboard's pipeline diagram light up
node-by-node in real time instead of only showing a final result.

### Why two state-key names differ from the node names

LangGraph forbids a node name colliding with a state field name. The natural
field names `threat_intel` and `root_cause` collided with node IDs
`threat_intel` / `root_cause`, so the **state fields** were renamed to
`threat_intel_report` / `root_cause_report` (see `graph/state.py`). The node
IDs, the `AGENT_NAMES` display labels, and the final assembled incident JSON
(`pipeline.py::_assemble_incident`) still use the friendly names
(`threat_intel`, `root_cause`) — only the internal LangGraph state dict uses
the `_report` suffix. If you add a new agent, watch for this collision.

## Ground truth, scenarios, and the accuracy score

`backend/app/scenarios.py` defines ~10 attack scenario templates (brute
force, SQL injection, ransomware, port scan, privilege escalation, data
exfiltration, lateral movement, phishing, DNS tunneling, and the masqueraded
file-upload scenario used by CYBER-10). Each scenario has:
- A generator function that produces randomized, realistic-looking log lines
  (random IPs, usernames, timestamps) on every run — so no two simulations
  look identical.
- A `ground_truth_mitre` list of the *actual* correct MITRE techniques for
  that attack type.

The **detection engine** classifies the attack independently, using its own
keyword rules — it does not get to see the ground truth. The **MITRE mapper
agent** (an LLM call) also proposes techniques independently. Only after both
have run does `scoring.py` compare the LLM's proposed techniques against the
scenario's ground truth to compute the accuracy score. This is why accuracy
is not always 100% — it's a genuine measurement of whether the agents figured
out the right answer, not a number that's hard-coded to look good.

## The CYBER-10 add-on: Malicious File Upload Scanner

`backend/app/upload_scanner.py` implements the magic-byte/MIME verification
required by the extra-credit spec. Logic, in order:
1. If the file's first bytes match a **known dangerous signature** (`MZ` for
   Windows PE, `\x7fELF`, a script shebang, a ZIP-family header, etc.), it is
   **always rejected**, regardless of what extension it was uploaded with.
2. Otherwise, if the declared extension has a known signature (png/jpg/gif/
   bmp/webp/pdf), the file's actual bytes must match that signature. A `.txt`
   file renamed to `.png` fails this check (plain text doesn't start with the
   PNG magic bytes `89 50 4E 47 0D 0A 1A 0A`) and is rejected with the error
   `"Invalid File Type"`, exactly matching the spec's verification target.
3. Otherwise the file is accepted.

**This ties into the multi-agent SOC, not just a standalone check**: every
*rejected* upload is turned into a synthetic "malicious upload" scenario
(`scenarios.py::_malicious_upload`, MITRE `T1036.008` Masquerading +
`T1204.002` User Execution) and run through the **full 9-agent pipeline**, so
a blocked upload shows up as a real investigated incident in the dashboard —
with analyst reasoning, MITRE mapping, and a response plan — not just a red
error toast. See `main.py::upload_file()`.

## Real-time behavior

Two background asyncio tasks start on FastAPI startup (`main.py::lifespan`):
- **Ambient log ticker** (every `LIVE_FEED_INTERVAL_SECONDS`, default 6s):
  publishes a single cosmetic benign log line to the live console. Purely
  visual — it does not touch the detection pipeline, so it costs nothing.
- **Autonomous incident loop** (every `AUTO_INCIDENT_INTERVAL_SECONDS`,
  default 120s): runs a full random-scenario pipeline automatically, so the
  SOC "catches something" on its own even if nobody clicks the simulate
  button. Set `AUTO_INCIDENT_INTERVAL_SECONDS=0` in `.env` to disable this if
  you want to control LLM spend tightly.

All of this — ambient logs, agent trace lines, completed incidents, upload
verdicts — is pushed over a single WebSocket (`/ws`) via an in-process pub/sub
broadcaster (`events.py`). The frontend (`frontend/app.js`) keeps a persistent
WS connection and reacts to each message type live; it also does a full
`/api/stats` + `/api/incidents` refetch after every completed incident so the
KPI tiles, charts, and table never drift from the database.

## Data model / persistence

SQLite (`backend/sentinelai.db`, gitignored) via `backend/app/db.py`. Two
tables: `incidents` (one row per completed pipeline run — the full report is
stored as a JSON blob in `data`, with a few columns denormalized for fast
`GROUP BY` queries used by `/api/stats`) and `upload_events` (one row per file
scanned). There is no `logs` table — ambient traffic is not persisted, only
the logs belonging to an actual incident (stored inside its JSON blob).

## Frontend

Single-page, no build step: `frontend/index.html` + `styles.css` + `app.js`,
served by FastAPI's `StaticFiles` mount. Chart.js (via CDN) renders the four
numeric charts; everything else (the agent pipeline diagram, badges, the live
console, the incident detail modal) is hand-built HTML/CSS driven by
`app.js`. Color usage follows Anthropic's internal dataviz design system:
attack categories get fixed-order categorical hues (fold to "Other" past 8),
severity uses the reserved status palette (critical/serious/warning/good) so
severity is never ambiguous with a regular series color, and the accuracy
trend line uses the sequential blue. The design is dark-first (a SOC
control-room look) with light-mode tokens defined via `data-theme="light"` on
`<html>`, though no theme toggle UI was wired up — only the token structure is
in place if you want to add one later.

## REST + WebSocket API surface

| Endpoint | Purpose |
|---|---|
| `GET /` | Serves the dashboard |
| `GET /api/health` | Liveness + whether an OpenRouter key is configured |
| `GET /api/scenarios` | List of available attack scenario templates |
| `POST /api/simulate` | Kick off a pipeline run (`{"scenario_id": "..."}` or `{}` for random) |
| `GET /api/incidents` | All persisted incidents, newest first |
| `GET /api/incidents/{id}` | One incident's full report |
| `POST /api/upload` | Multipart file upload → scanner verdict (+ triggers an incident if rejected) |
| `GET /api/uploads` | Upload scan history |
| `GET /api/stats` | Aggregate counts for the KPI tiles and charts |
| `WS /ws` | Live event stream (ambient logs, agent steps, incident/upload completions) |

## Running it locally

```
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
# backend\.env already has OPENROUTER_API_KEY set — edit it if you rotate the key
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

Then open `http://127.0.0.1:8000/`. The `.env` file (with the real API key)
is gitignored and only exists locally — `backend/.env.example` is the
committed template.

## Known limitations (be upfront about these)

- Threat intelligence is **simulated** by the LLM, not a real external feed.
  This is stated in the UI and in the agent's own output.
- Free OpenRouter models can be slower/less consistent than paid models;
  the fallback-model chain and deterministic fallback logic exist specifically
  to keep the demo reliable despite that.
- SQLite + in-process pub/sub means this is single-process only — fine for a
  demo/portfolio project, not designed for multi-instance deployment.
- No authentication on any endpoint. Do not expose this publicly as-is.
