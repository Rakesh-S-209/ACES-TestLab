# A.C.E.S. Architecture Reference

> Produced during Phase 1 audit of `Rakesh-S-209/ACES` (commit `4c7a1dc`).  
> All claims are grounded in the actual source files listed below.

---

## 1. Repository Layout

```
PROJECT FOLDER/
├── run.py                         # Application entry point / startup orchestrator
├── train_behavior_model.py        # Offline IsolationForest training script
├── requirements.txt               # Pinned Python dependencies
├── pytest.ini                     # Pytest configuration
├── data/
│   └── honey_tokens/
│       └── db_config.json         # Filesystem honeytoken (decoy credential file)
├── src/
│   ├── __init__.py
│   ├── auth/
│   │   └── db.py                  # SQLite persistence layer (~34 KB)
│   ├── deception/
│   │   ├── port_trap.py           # Multi-port TCP honeyport daemon
│   │   └── token_watcher.py       # Watchdog-backed filesystem honeytoken watcher
│   ├── portal/
│   │   ├── gateway.py             # Abstract base + IP-ban middleware + Layer-7 honeytokens
│   │   ├── financial_shell.py     # Concrete portal shell (BehaviorScorer integration)
│   │   └── static/
│   │       ├── index.html         # React SPA shell
│   │       ├── portal.html        # NorthStar Capital decoy portal
│   │       └── soc.html           # SOC analyst dashboard (~78 KB vanilla JS/Chart.js)
│   ├── soc_pipeline/
│   │   ├── event_hub.py           # asyncio pub/sub event bus
│   │   ├── soar_engine.py         # SOAR orchestrator (ban, revoke, enrich, alert)
│   │   ├── intel_aggregator.py    # AbuseIPDB + offline fallback reputation lookup
│   │   ├── abuseipdb_client.py    # AbuseIPDB v2 HTTP client
│   │   └── ws_dashboard.py        # asyncio HTTP + WebSocket server (~81 KB)
│   └── zero_trust/
│       ├── models.py              # Core data models (dataclasses + enums)
│       ├── scorer.py              # IsolationForest BehaviorScorer
│       └── validation.py          # TelemetryVector field validators
├── frontend-aces/                 # React/Vite SPA (separate project, not under test)
│   └── src/pages/...
└── tests/
    ├── __init__.py
    ├── test_models.py
    ├── test_scorer.py
    ├── test_soar.py
    ├── test_event_hub.py
    ├── test_deception.py
    ├── test_validation.py
    ├── test_quarantine_workflow.py
    ├── test_port_trap_integration.py
    └── test_final_integration.py
```

---

## 2. Detection Pipeline

```
Kali Linux Attacker
  ├─ TCP scan (nmap/nc) ──────────────────► PortTrap (ports 22, 445, 3389)
  │                                               │ ban_ip() + log_port_trap_hit()
  │                                               │ publish(PORT_TRAP AlertEvent)
  ├─ HTTP probe (gobuster) ───────────────► SOCDashboardServer._dispatch_inner()
  │   hits WEB_HONEYTOKEN_PATHS                   │ check_web_honeytoken()
  │                                               │ ban_ip() + log_honeytoken_event()
  │                                               │ publish(HONEYTOKEN_ACCESS AlertEvent)
  ├─ File access (cat db_config.json) ───► HoneytokenWatcher (watchdog thread)
  │                                               │ call_soon_threadsafe → EventHub queue
  │                                               │ publish(HONEYTOKEN_ACCESS AlertEvent)
  └─ Normal browsing (POST /api/action) ─► BasePortalShell.run()
       ├─ Guard 1: public-page bypass               │
       ├─ Guard 2: is_banned() check                │
       └─ FinancialShell.handle_user_action()        │
              BehaviorScorer.predict(TelemetryVector) │
              score ≥ 0.50 → publish(AI_ANOMALY)     │
              score ≥ 0.85 → SOAREngine.trigger_response()
                                                      │
                                               EventHub (asyncio.Queue + fan-out)
                                                      │
                                    ┌─────────────────┼──────────────────┐
                                    ▼                                     ▼
                              SOAREngine                          broadcast_loop
                           ① blacklist IP (in-memory)         WebSocket push to
                           ② ban_ip() + revoke_sessions()      all SOC clients
                           ③ fetch_reputation() (AbuseIPDB)
                           ④ publish enriched AI_ANOMALY
                           ⑤ append SOARResult to audit log
                                    │
                                    ▼
                          SOC Dashboard (soc.html)
                          ├── Live Event Stream
                          ├── Triage Queue + [Alert] / [Remove Ban]
                          ├── Deception & Honeytoken Panel
                          ├── Score Distribution (KDE)
                          └── Baseline Timeline (Chart.js)
```

---

## 3. Component Reference

### 3.1 Data Models (`src/zero_trust/models.py`)

| Class | Purpose |
|---|---|
| `TelemetryVector` | 5-field behavioral payload; `to_feature_array()` yields 11 floats |
| `SessionRecord` | In-memory session state; `revocation_delta_ms` property |
| `AlertEvent` | Structured event across all three detection layers; `to_json()` |
| `IPReputationReport` | AbuseIPDB enrichment result |
| `GatewayDecision` | Gateway policy outcome (ALLOW / BLOCK / REVOKE) |
| `SOARResult` | SOAR pipeline result (`success`, `delta_ms`) |
| `SessionStatus` | Enum: ACTIVE / REVOKED / EXPIRED |
| `AlertType` | Enum: AI_ANOMALY / HONEYTOKEN_ACCESS / PORT_TRAP |
| `PolicyAction` | Enum: ALLOW / BLOCK / REVOKE |

### 3.2 BehaviorScorer (`src/zero_trust/scorer.py`)

- Backed by scikit-learn `IsolationForest` (100 estimators, contamination 0.05 default).
- **Two modes**: `from_pkl()` (offline-trained, requires `data/behavior_model.pkl`) and `fit(baseline_vectors)` (synthetic, suitable for tests).
- Normalisation: `score = (0.5 - clamp(raw, -0.5, 0.5)) / 1.0` → range [0, 1].
- Thresholds: `BASELINE_THRESHOLD = 0.50` (SOC alert), `ESCALATION_THRESHOLD = 0.85` (auto-ban).
- `score_detailed()` returns a dict suitable for the `/api/telemetry/score` endpoint.
- `_telemetry_to_flow_features()` maps a `TelemetryVector` (5 fields) to 29 flow features for the pkl model.

### 3.3 Validation (`src/zero_trust/validation.py`)

Five field validators, each raising `ValueError` with a named message:

| Field | Constraint |
|---|---|
| `click_speed_intervals` | Non-empty list[float], len ≤ 1000, all ≥ 0.0, all finite |
| `page_path_weights` | Non-empty, all in [0.0, 1.0], all finite |
| `sequence_transitions` | list[int], each in [1, 999 999] |
| `session_duration_ms` | float in [0.0, 86 400 000] (24 h) |
| `request_rate_per_sec` | float in [0.0, 10 000.0] |

### 3.4 EventHub (`src/soc_pipeline/event_hub.py`)

- Module-level `_QUEUE: asyncio.Queue[AlertEvent]` singleton.
- `_SUBSCRIBERS: list[asyncio.Queue[AlertEvent]]` — per-subscriber fan-out queues.
- `publish()` fans out to all registered subscribers; parks in `_QUEUE` when no subscribers exist (event not lost).
- `subscribe()` is an async generator — registers sub-queue on entry, removes on exit.
- `get_queue()` returns the raw queue for thread-safe bridging (`call_soon_threadsafe`).
- **Known isolation issue**: module-level globals persist across tests unless the module is reloaded. All test files call `importlib.reload(_hub_module)` before constructing a fresh `EventHub`.

### 3.5 PortTrap (`src/deception/port_trap.py`)

- Binds to 22, 445, 3389 by default; accepts any `ports=` list.
- `handle_connection()`: extracts IP → `blacklist.add()` → `ban_ip()` (SQLite) → `publish(PORT_TRAP)` → zero bytes → close within 100 ms.
- `OSError` on bind (privilege / port-in-use) is caught, logged, and skipped — other ports remain active.

### 3.6 HoneytokenWatcher (`src/deception/token_watcher.py`)

- Watchdog `Observer` runs in a **daemon thread**.
- `_HoneytokenEventHandler.on_any_event()` filters: (1) skip directories, (2) only fire on `db_config.json` basename.
- Alert bridged via `loop.call_soon_threadsafe(hub.get_queue().put_nowait, alert)`.
- `source_ip` is always `"local"` (no network IP available for filesystem events).

### 3.7 SOAREngine (`src/soc_pipeline/soar_engine.py`)

- Two entry points: `start_orchestrator()` (subscriber loop) and `trigger_response()` (direct Gateway call).
- Monitor-only mode (`monitor_only=True`): logs and alerts without banning.
- Loopback guard: skips containment for `127.0.0.1`, `::1`, `localhost`, `127.*`.
- Role-priority inspection: Admin accounts escalated before Engineer/Guest.
- `_revoke_sessions_for_ip()` mutates `ACTIVE_SESSIONS` in-memory dict.
- Reputation fetch via `ThreatIntelAggregator` (AbuseIPDB API or offline fallback).

### 3.8 Database (`src/auth/db.py`)

SQLite with WAL mode. Key tables:

| Table | Purpose |
|---|---|
| `users` | Hashed credentials for three built-in accounts |
| `sessions` | JWT-like token → session binding |
| `banned_ips` | Hard-banned IP addresses |
| `port_trap_hits` | Per-port connection count log |
| `honeytoken_events` | Structured event log (honeytoken + SOAR) |
| `telemetry_events` | AI scoring events with feature data |
| `abuse_reports` | AbuseIPDB report outcomes |

Key functions: `init_db()`, `ban_ip()`, `unban_ip()`, `is_banned()`, `revoke_sessions_for_ip()`, `log_port_trap_hit()`, `log_honeytoken_event()`, `get_active_sessions()`.

---

## 4. Startup Process (`run.py`)

1. Load `.env` (Python-dotenv).
2. Call `auth_db.init_db(DB_PATH)` — creates schema if absent.
3. Instantiate `EventHub`, `ACTIVE_SESSIONS`, `PERIMETER_BLACKLIST`.
4. Load `BehaviorScorer.from_pkl()` or fall back to `scorer.fit()`.
5. Start `HoneytokenWatcher` (daemon thread).
6. Start `PortTrap.start_server()` (binds decoy ports).
7. Start `SOAREngine.start_orchestrator()` (async subscriber loop).
8. Start `SOCDashboardServer` (HTTP + WebSocket on port 8000).

---

## 5. External Dependencies

| Package | Purpose | CI-safe? |
|---|---|---|
| `scikit-learn` | IsolationForest + RobustScaler | ✅ |
| `watchdog` | Filesystem monitoring | ✅ (mock in tests) |
| `python-dotenv` | `.env` loading | ✅ |
| `aiohttp` | AbuseIPDB HTTP client | ✅ (offline fallback covers CI) |
| `websockets` | WebSocket protocol | ✅ |
| `pandas` | Training data processing | ✅ (not needed for tests) |
| `hypothesis` | Property-based testing | ✅ |
| `pytest-asyncio` | Async test support | ✅ |
| `httpx` | HTTP test client | ✅ |
| AbuseIPDB API key | Threat intel enrichment | ❌ (offline fallback used) |
| `data/behavior_model.pkl` | Pre-trained model bundle | ❌ (synthetic fit used) |
| Port 8000 | HTTP/WebSocket server | ⚠️ (ephemeral ports in tests) |
| Ports 22, 445, 3389 | PortTrap decoy ports | ⚠️ (mocked / ephemeral in tests) |

---

## 6. OS and Privilege Notes

- **Port 445 (SMB)**: Windows blocks binding by the OS `Server` service. Tests use ephemeral high ports.
- **Port 22 (SSH)**: May require elevated privileges on Linux. Tests use ephemeral ports.
- **watchdog**: Cross-platform; `Observer` uses platform-native API (inotify / FSEvents / ReadDirectoryChangesW).
- **SQLite WAL mode**: Requires filesystem support; `tmp_path` (pytest) is always safe.
