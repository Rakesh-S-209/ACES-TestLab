# A.C.E.S. Test Plan

> Phase 1 deliverable.  Describes what will be tested, why, and how.

---

## 1. Test Suite Overview

```
tests/
  conftest.py                    # Shared fixtures
  unit/
    test_behavior_scorer.py      # BehaviorScorer: fit, predict, score range, normalisation
    test_event_models.py         # TelemetryVector, SessionRecord, AlertEvent, etc.
    test_ip_blocking.py          # check_web_honeytoken, BasePortalShell ban check
    test_honeytoken_logic.py     # _HoneytokenEventHandler filtering + thread bridging
  integration/
    test_soar_pipeline.py        # SOAREngine: trigger_response, process_event, audit log
    test_event_hub.py            # EventHub: publish, subscribe, fan-out, ordering
    test_database_events.py      # SQLite: schema, CRUD, ban, session, event tables
    test_session_revocation.py   # Session lifecycle: revoke, expired, delta_ms
  security/
    test_input_validation.py     # All five TelemetryVector field validators
    test_access_control.py       # Banned IP rejection, monitor-only mode
    test_blocked_requests.py     # Post-ban gateway behaviour
  regression/
    test_known_defects.py        # One test per documented defect
  fixtures/
    __init__.py
```

> **Note**: The upstream repository already has a `tests/` directory with 9 test files.  
> This layout extends and reorganises that work into the structure above during Phases 2–6.  
> The existing tests are preserved and incorporated.

---

## 2. Test Cases by Component

### 2.1 TelemetryVector (`test_event_models.py`)

| ID | Description | Type |
|---|---|---|
| TV-01 | `to_feature_array()` returns a list of exactly 11 floats | Unit |
| TV-02 | All elements of `to_feature_array()` are finite | Unit |
| TV-03 | `to_feature_array()` raises `ValueError` on NaN input | Unit |
| TV-04 | `to_feature_array()` raises `ValueError` on Inf input | Unit |
| TV-05 | Property: `to_feature_array()` always finite for any valid vector (Hypothesis) | Property |

### 2.2 Validation (`test_input_validation.py`)

| ID | Description | Type |
|---|---|---|
| VAL-01 | Empty `click_speed_intervals` raises `ValueError` | Unit |
| VAL-02 | `click_speed_intervals` > 1000 items raises `ValueError` | Unit |
| VAL-03 | Negative click interval raises `ValueError` | Unit |
| VAL-04 | NaN / Inf click interval raises `ValueError` | Unit |
| VAL-05 | `page_path_weights` out of [0, 1] raises `ValueError` | Unit |
| VAL-06 | `sequence_transitions` with 0 or > 999999 raises `ValueError` | Unit |
| VAL-07 | Float in `sequence_transitions` raises `ValueError` | Unit |
| VAL-08 | `session_duration_ms` > 86400000 raises `ValueError` | Unit |
| VAL-09 | Negative `session_duration_ms` raises `ValueError` | Unit |
| VAL-10 | `request_rate_per_sec` > 10000 raises `ValueError` | Unit |
| VAL-11 | Negative `request_rate_per_sec` raises `ValueError` | Unit |
| VAL-12 | Boundary values at limits pass validation | Unit |
| VAL-13 | Property: any out-of-range value always rejected (Hypothesis) | Property |

### 2.3 BehaviorScorer (`test_behavior_scorer.py`)

| ID | Description | Type |
|---|---|---|
| SCO-01 | `predict()` before `fit()` raises `NotFittedError` | Unit |
| SCO-02 | `fit()` succeeds with valid baseline vectors | Unit |
| SCO-03 | `fit()` with invalid vector raises `ValueError` | Unit |
| SCO-04 | `predict()` returns float in [0.0, 1.0] | Unit |
| SCO-05 | Normalisation: raw = -0.5 → score = 1.0 | Unit |
| SCO-06 | Normalisation: raw = +0.5 → score = 0.0 | Unit |
| SCO-07 | Normalisation: raw = 0.0 → score = 0.5 | Unit |
| SCO-08 | Same input → same score (determinism) | Unit |
| SCO-09 | High-rate anomalous vector tends to score higher than normal | Unit |
| SCO-10 | `score_detailed()` returns required keys | Unit |
| SCO-11 | `score_detailed()` `is_anomaly` correct relative to threshold | Unit |
| SCO-12 | `from_pkl()` raises `FileNotFoundError` for missing file | Unit |
| SCO-13 | Property: score always in [0, 1] for any valid vector (Hypothesis) | Property |
| SCO-14 | Property: normalisation formula always in [0, 1] for any raw value (Hypothesis) | Property |

### 2.4 EventHub (`test_event_hub.py`)

| ID | Description | Type |
|---|---|---|
| HUB-01 | Single subscriber receives published event | Integration |
| HUB-02 | All N subscribers receive the same event (fan-out) | Integration |
| HUB-03 | Events delivered in strict publication order | Integration |
| HUB-04 | Remaining subscribers receive events after one disconnects | Integration |
| HUB-05 | `publish()` does not block when no subscribers present | Integration |
| HUB-06 | `delivery_count` increments correctly | Integration |
| HUB-07 | `subscriber_count` decrements after consumer exits | Integration |
| HUB-08 | `get_queue()` returns an `asyncio.Queue` | Unit |

### 2.5 PortTrap (`test_ip_blocking.py`, integration)

| ID | Description | Type |
|---|---|---|
| PT-01 | `handle_connection()` never calls `writer.write()` | Unit |
| PT-02 | Source IP added to blacklist after connection | Unit |
| PT-03 | Exactly one `PORT_TRAP` alert published per connection | Unit |
| PT-04 | Alert `timestamp_ms` is within test wall-clock bounds | Unit |
| PT-05 | `None` peername falls back to `"unknown"` source_ip | Unit |
| PT-06 | `start_server()` on an unavailable port does not raise | Integration |
| PT-07 | `start_server()` with custom `ports=` list binds only those ports | Integration |
| PT-08 | `stop()` closes all servers and empties `listening_ports` | Integration |

### 2.6 HoneytokenWatcher (`test_honeytoken_logic.py`)

| ID | Description | Type |
|---|---|---|
| HT-01 | Constructor creates `db_config.json` in watch directory | Unit |
| HT-02 | Honeytoken file contains valid JSON | Unit |
| HT-03 | Directory event does not publish any alert | Unit |
| HT-04 | File event on `db_config.json` enqueues exactly one alert | Unit |
| HT-05 | Alert is `HONEYTOKEN_ACCESS` type | Unit |
| HT-06 | Alert `source_ip` is `"local"` | Unit |
| HT-07 | Alert `affected_path` is absolute | Unit |
| HT-08 | Alert `timestamp_ms` within wall-clock bounds | Unit |
| HT-09 | Event on non-target file ignored | Unit |
| HT-10 | Thread-safe bridging uses `call_soon_threadsafe` | Unit |
| HT-11 | Property: directory events always ignored (Hypothesis) | Property |

### 2.7 SOAREngine (`test_soar_pipeline.py`)

| ID | Description | Type |
|---|---|---|
| SOA-01 | `trigger_response()` adds IP to blacklist | Integration |
| SOA-02 | `trigger_response()` sets session status to REVOKED | Integration |
| SOA-03 | `trigger_response()` publishes `AI_ANOMALY` alert | Integration |
| SOA-04 | Alert `anomaly_score` matches the input score | Integration |
| SOA-05 | Missing session handled without raising | Integration |
| SOA-06 | Audit log grows by one per `trigger_response()` call | Integration |
| SOA-07 | `result.delta_ms` is non-negative | Integration |
| SOA-08 | Memory eviction completes in < 5 ms | Integration |
| SOA-09 | All sessions for same IP revoked | Integration |
| SOA-10 | Loopback IP (`127.0.0.1`) is never blacklisted | Integration |
| SOA-11 | Monitor-only mode does not ban IP | Integration |
| SOA-12 | Property: IP always blacklisted for any score > 0.75 (Hypothesis) | Property |
| SOA-13 | Property: eviction always < 5 ms (Hypothesis) | Property |

### 2.8 Database (`test_database_events.py`)

| ID | Description | Type |
|---|---|---|
| DB-01 | `init_db()` creates all tables | Integration |
| DB-02 | `ban_ip()` + `is_banned()` round-trip | Integration |
| DB-03 | `unban_ip()` removes ban record | Integration |
| DB-04 | `is_banned()` returns False for unknown IP | Integration |
| DB-05 | `revoke_sessions_for_ip()` sets sessions to REVOKED | Integration |
| DB-06 | `log_port_trap_hit()` persists row | Integration |
| DB-07 | `log_honeytoken_event()` persists row | Integration |
| DB-08 | `get_active_sessions()` returns only active sessions | Integration |
| DB-09 | Reopening the DB preserves previous bans | Integration |
| DB-10 | Two tests using `tmp_path` never share state | Integration |

### 2.9 Gateway / Access Control (`test_access_control.py`, `test_blocked_requests.py`)

| ID | Description | Type |
|---|---|---|
| GW-01 | `check_web_honeytoken()` returns `True` for bait paths | Security |
| GW-02 | `check_web_honeytoken()` bans IP in SQLite | Security |
| GW-03 | `check_web_honeytoken()` returns `False` for normal paths | Security |
| GW-04 | `BasePortalShell.run()` returns `BLOCK` for banned IP | Security |
| GW-05 | Public action types bypass ban check | Security |
| GW-06 | Monitor-only mode skips SQLite ban write | Security |
| GW-07 | Banned IP GET → HTTP 403 quarantine page | Integration |
| GW-08 | Clean IP GET → HTTP 200 / 302 | Integration |
| GW-09 | Honeytoken hit → ban → subsequent request → 403 | Integration |

---

## 3. Test Execution Commands

```bash
# All tests
pytest

# Unit tests only (fast)
pytest -m unit

# Integration tests
pytest -m integration

# Security / negative tests
pytest -m security

# Regression suite
pytest -m regression

# With coverage
pytest --cov=src --cov-report=html --cov-report=term-missing

# Generate JUnit XML
pytest --junitxml=reports/junit.xml

# Generate HTML report
pytest --html=reports/report.html --self-contained-html

# All reporting in one command
pytest \
  --cov=src \
  --cov-report=html:reports/coverage_html \
  --cov-report=term-missing \
  --junitxml=reports/junit.xml \
  --html=reports/report.html \
  --self-contained-html
```

---

## 4. Test Data

| Fixture | Description |
|---|---|
| `normal_vector` | Low rate (1 rps), moderate click intervals (100–200 ms) |
| `anomalous_vector` | High rate (9999 rps), very short intervals (0.001 ms) |
| `fitted_scorer` | BehaviorScorer trained on 120 synthetic normal vectors |
| `tmp_db` | Temporary SQLite DB via `tmp_path` |
| `fresh_hub` | New EventHub with reloaded module globals |
| `blank_sessions` | Empty `dict[str, SessionRecord]` |
| `blank_blacklist` | Empty `set[str]` |

---

## 5. Acceptance Criteria

A phase is complete when:
- All new tests pass with no unexpected failures.
- No test uses `time.sleep()` for synchronisation longer than 200 ms.
- No test shares state with another test (isolation verified by running in random order).
- Coverage does not regress from the previous phase.
- All `# pragma: no cover` exclusions are justified in comments.
