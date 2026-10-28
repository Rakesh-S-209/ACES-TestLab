# ACES-TestLab Implementation Plan

---

## Phase Overview

| Phase | Goal | Status |
|---|---|---|
| **1** | Repository audit, architecture doc, test strategy, plan, defect log | ✅ Complete |
| 2 | Test infrastructure: conftest.py, fixtures, markers, CI skeleton | ⏳ Next |
| 3 | Unit tests: scorer, models, validation, event_hub, honeytoken logic | Pending |
| 4 | Integration tests: SOAR pipeline, database, session revocation | Pending |
| 5 | Integration tests: PortTrap, quarantine workflow, honeytoken watcher | Pending |
| 6 | Regression tests: DEF-001, DEF-002, DEF-003 + any new defects | Pending |
| 7 | Coverage config, Ruff linting, GitHub Actions CI | Pending |
| 8 | Full run, fix failures, document remaining limitations | Pending |
| 9 | Evidence capture, portfolio preparation | Pending |

---

## Phase 1 Findings Summary

### Repository structure (verified against GitHub API)

```
PROJECT FOLDER/
  src/
    auth/db.py                   # 34 KB — SQLite layer
    deception/port_trap.py       # 11 KB — TCP honeyport
    deception/token_watcher.py   # 7.6 KB — filesystem watcher
    portal/gateway.py            # 9 KB — IP ban + Layer-7 honeytokens
    portal/financial_shell.py    # 10.6 KB — portal with BehaviorScorer
    soc_pipeline/event_hub.py    # 4.6 KB — pub/sub bus
    soc_pipeline/soar_engine.py  # 24.8 KB — SOAR orchestrator
    soc_pipeline/intel_aggregator.py  # 7.4 KB
    soc_pipeline/abuseipdb_client.py  # 9.1 KB
    soc_pipeline/ws_dashboard.py # 81 KB — HTTP + WebSocket server
    zero_trust/models.py         # 10.4 KB — data models
    zero_trust/scorer.py         # 13.9 KB — IsolationForest scorer
    zero_trust/validation.py     # 6.7 KB — field validators
  tests/
    test_models.py, test_scorer.py, test_soar.py, test_event_hub.py,
    test_deception.py, test_validation.py, test_quarantine_workflow.py,
    test_port_trap_integration.py, test_final_integration.py
  pytest.ini                     # asyncio_mode = auto, testpaths = tests
  requirements.txt               # scikit-learn, watchdog, hypothesis, pytest-asyncio, httpx
```

### Existing test coverage (upstream)

The upstream repo already has **9 test files** with strong coverage of:
- `models.py` — all dataclasses, Hypothesis property tests
- `scorer.py` — fit, predict, normalisation formula, non-finite input
- `validation.py` — all five field validators, Property 7
- `event_hub.py` — fan-out, ordering, subscriber lifecycle
- `soar_engine.py` — trigger_response, eviction timing, Properties 11–14
- `deception/` — PortTrap zero-bytes, HoneytokenWatcher filtering, Properties 15–19
- `test_quarantine_workflow.py` — end-to-end quarantine pipeline
- `test_port_trap_integration.py` — real TCP bind and connect
- `test_final_integration.py` — full pipeline integration

### Testing gaps identified

1. **`src/auth/db.py`** — No dedicated database unit tests. The quarantine workflow tests touch `init_db()` and `ban_ip()` but don't systematically cover `log_port_trap_hit()`, `log_honeytoken_event()`, `get_active_sessions()`, transaction rollback, or DB-reopening behaviour.

2. **`score_detailed()`** — Not tested. Returns dict with `anomaly_score`, `baseline_threshold`, `is_anomaly`, `timestamp`. The `is_anomaly` flag logic and timestamp format are untested.

3. **`BehaviorScorer.from_pkl()`** failure modes — Only the success path (missing file → `FileNotFoundError`) needs testing. The "missing key in bundle" branch is untested.

4. **`BasePortalShell.run()`** public-page bypass — Not tested in isolation. It is covered implicitly by the quarantine workflow integration test but not as a unit test.

5. **`SOAREngine.start_orchestrator()` / `stop()`** — The subscriber loop path is not directly tested. Only `trigger_response()` (direct call) is tested.

6. **`SOAREngine.monitor_only` mode via `_process_event()`** — The `trigger_response()` monitor-only path is tested, but the `start_orchestrator()` → `_process_event()` monitor-only path is not.

7. **`HoneytokenWatcher.start()` / `stop()`** — Lifecycle methods not tested. Only the event handler is tested via mock.

8. **`ThreatIntelAggregator` live API path** — Not tested (by design; offline fallback covers CI).

9. **Regression for DEF-003** — `bool` in `click_speed_intervals` slips through validation. No existing test catches this.

10. **`WEB_HONEYTOKEN_PATHS` — non-bait paths correctly pass through** — The upstream tests check one path; systematic parametrized coverage of all 40+ paths is missing.

### Risks and assumptions

| Risk | Impact | Mitigation |
|---|---|---|
| `behavior_model.pkl` not in repo | pkl-mode scorer cannot be tested | Use synthetic `scorer.fit()` for all tests |
| Windows port 445 blocked by OS | `PortTrap` cannot bind 445 | Tests use ephemeral ports ≥ 18000 |
| EventHub module-level globals | Test pollution | `importlib.reload()` in every hub fixture |
| `ws_dashboard.py` is 81 KB | Complex; integration tests need real server | Use raw TCP/HTTP in integration tests |
| `asyncio_mode = auto` in pytest.ini | All async tests auto-managed | Compatible with our approach |
| Hypothesis `deadline` | Slow tests fail with `DeadlineExceeded` | Add `@settings(deadline=None)` to slow tests |

---

## Phase 2 Plan

### Deliverables
1. `tests/conftest.py` — shared fixtures
2. Extended `pytest.ini` with markers
3. `tests/unit/`, `tests/integration/`, `tests/security/`, `tests/regression/` directory structure
4. `tests/fixtures/__init__.py`
5. `.github/workflows/ci.yml` skeleton
6. `pyproject.toml` with Ruff configuration

### Key fixtures to implement
```python
@pytest.fixture
def fresh_hub() -> EventHub:
    """Reloaded EventHub with clean module globals."""

@pytest.fixture
def tmp_db(tmp_path) -> Path:
    """Temporary SQLite database, schema initialised."""

@pytest.fixture
def blank_blacklist() -> set[str]:
    """Empty PERIMETER_BLACKLIST for test isolation."""

@pytest.fixture
def blank_sessions() -> dict:
    """Empty ACTIVE_SESSIONS dict for test isolation."""

@pytest.fixture
def normal_vector() -> TelemetryVector:
    """Benign behavioral vector (low rate, moderate clicks)."""

@pytest.fixture
def anomalous_vector() -> TelemetryVector:
    """Anomalous vector (high rate, very short clicks)."""

@pytest.fixture
def fitted_scorer() -> BehaviorScorer:
    """Scorer trained on 120 synthetic normal vectors, random_state=42."""
```
