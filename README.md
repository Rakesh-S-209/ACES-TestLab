# ACES-TestLab

Automated Security Regression & Validation Suite for  
**A.C.E.S. — Autonomous Cyber-defence & Enforcement System**

> This repository contains only the test engineering work.  
> The production application lives at [Rakesh-S-209/ACES](https://github.com/Rakesh-S-209/ACES).

---

## What is this?

ACES-TestLab is a comprehensive, maintainable automated testing suite for the A.C.E.S. Zero Trust security platform. It exercises the real production components to validate detection accuracy, prevent regressions, and demonstrate SDET-level engineering discipline.

The suite covers:

| Layer | What is tested |
|---|---|
| **BehaviorScorer** | IsolationForest scoring, normalisation formula, model loading, boundary conditions |
| **Validation** | All five `TelemetryVector` field validators, boundary values, type checks |
| **EventHub** | Async pub/sub fan-out, event ordering, subscriber lifecycle, thread-safe bridging |
| **PortTrap** | Zero-bytes policy, blacklist update, alert publication, port bind failure |
| **HoneytokenWatcher** | File event filtering, directory event rejection, thread-safe queue bridging |
| **SOAREngine** | IP blacklisting, session revocation, audit log, eviction timing, monitor-only mode |
| **Database** | Schema creation, ban CRUD, session management, event logging, reopening |
| **Gateway** | Web honeytoken hit detection, ban-on-hit, blocked IP rejection, quarantine page |
| **Regression** | One test per documented defect |

---

## Project Status

| Phase | Description | Status |
|---|---|---|
| 1 | Repository audit, architecture, test strategy & plan | ✅ Complete |
| 2 | Test infrastructure: conftest.py, markers, CI skeleton | ✅ Complete |
| 3 | Unit tests: scorer, models, honeytoken logic, ip blocking | ✅ Complete |
| 4 | Integration tests: SOAR pipeline, event hub, database, sessions | ✅ Complete |
| 5 | Security tests: input validation, access control, blocked requests | ✅ Complete |
| 6 | Regression tests: DEF-001, DEF-002, DEF-003 | ✅ Complete |
| 7 | Coverage config, Ruff, GitHub Actions CI | ✅ Complete |
| 8 | Full run, fix failures, document limitations | ⏳ Run locally |
| 9 | Evidence capture, portfolio presentation | ⏳ Pending run |

---

## Prerequisites

1. **Python 3.11** (matches upstream requirement)
2. Clone the production ACES repository:
   ```bash
   git clone https://github.com/Rakesh-S-209/ACES.git
   ```
3. From the `PROJECT FOLDER/` inside that clone, install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install pytest-cov pytest-html ruff
   ```

> The test suite runs in-place against the production source tree.  
> Clone `ACES-TestLab` into the same parent directory or copy its `tests/` subtree over the existing `tests/` directory inside `PROJECT FOLDER/`.

---

## Running Tests

```bash
# All tests
pytest

# Unit tests only (fast, no I/O)
pytest -m unit

# Integration tests
pytest -m integration

# Security / negative tests
pytest -m security

# Regression suite
pytest -m regression

# With coverage report
pytest --cov=src --cov-report=html:reports/coverage_html --cov-report=term-missing

# Full reporting pipeline
pytest \
  --cov=src \
  --cov-report=html:reports/coverage_html \
  --cov-report=term-missing \
  --junitxml=reports/junit.xml \
  --html=reports/report.html \
  --self-contained-html

# Lint
ruff check src/ tests/
```

---

## Test Architecture

```
tests/
  conftest.py                    # Shared fixtures (fresh_hub, tmp_db, fitted_scorer, …)
  unit/
    test_behavior_scorer.py      # BehaviorScorer unit + property-based tests
    test_event_models.py         # TelemetryVector, SessionRecord, AlertEvent
    test_ip_blocking.py          # check_web_honeytoken, BasePortalShell ban check
    test_honeytoken_logic.py     # _HoneytokenEventHandler filtering
  integration/
    test_soar_pipeline.py        # SOAREngine: trigger_response, revoke, eviction
    test_event_hub.py            # EventHub: fan-out, ordering, disconnection
    test_database_events.py      # SQLite: schema, CRUD, events, reopening
    test_session_revocation.py   # Session lifecycle and delta_ms
  security/
    test_input_validation.py     # TelemetryVector field validators
    test_access_control.py       # Banned IP rejection, monitor-only
    test_blocked_requests.py     # Post-ban HTTP quarantine behaviour
  regression/
    test_known_defects.py        # DEF-001, DEF-002, DEF-003
  fixtures/
    __init__.py
```

---

## Pytest Markers

| Marker | Description |
|---|---|
| `@pytest.mark.unit` | Fast, no I/O, no network |
| `@pytest.mark.integration` | Multiple components, may open loopback ports |
| `@pytest.mark.security` | Negative / adversarial input tests |
| `@pytest.mark.regression` | Tests for documented defects |
| `@pytest.mark.slow` | Property-based tests with many examples or no deadline |

---

## Test Isolation Guarantees

- Every test that needs a database uses `tmp_path / "test.db"` — the real application database is never touched.
- Every test that creates an `EventHub` calls `importlib.reload()` first to reset module-level globals.
- Scorer tests use synthetic `scorer.fit()` — the production `behavior_model.pkl` is not required.
- AbuseIPDB is always called with `timeout_s=0.000_001` in tests, forcing the offline fallback path.
- TCP ports used in integration tests are in the 18000–19999 range to avoid privilege issues.
- `watchdog` tests use `tmp_path` directories — real credential files are never touched.

---

## Documented Defects

See [`docs/defect_log.md`](docs/defect_log.md) for full details.

| ID | Title | Severity | Status |
|---|---|---|---|
| DEF-001 | EventHub global state leaks across tests | Medium | Documented / Mitigated |
| DEF-002 | `_telemetry_to_flow_features` semantic duplication at positions 3–4 | Low | Documentation gap |
| DEF-003 | `bool` in `click_speed_intervals` not rejected by validator | Medium | Open |

---

## Documentation

| Document | Description |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Full component reference and pipeline diagram |
| [`docs/test_strategy.md`](docs/test_strategy.md) | Test levels, isolation strategy, toolchain, CI plan |
| [`docs/test_plan.md`](docs/test_plan.md) | Test cases by component with IDs |
| [`docs/defect_log.md`](docs/defect_log.md) | Defect descriptions, root causes, regression tests |
| [`docs/implementation_plan.md`](docs/implementation_plan.md) | Phase-by-phase plan, gaps identified, risks |

---

## Limitations

- The production `behavior_model.pkl` (trained on 362 K real network flows) is not committed to the repository. All scorer tests use synthetic training data via `scorer.fit()`. The pkl-mode code path is tested only for failure handling (missing file, missing key).
- Binding to ports 22 and 445 requires elevated privileges on most systems. Integration tests for PortTrap use ephemeral ports (18000+).
- The AbuseIPDB live API is never called in automated tests. The offline fallback is tested instead.
- `ws_dashboard.py` (81 KB) is not unit-tested at the handler level. It is covered only through raw HTTP integration tests.
- Windows SMB system service owns port 445; that specific port is excluded from CI tests.

---

## Portfolio Evidence Plan

After Phase 8 completion:

1. **Pytest terminal output** — `pytest -v --tb=short` screenshot
2. **HTML test report** — `reports/report.html` screenshot
3. **Coverage report** — `reports/coverage_html/index.html` screenshot
4. **Failing regression test** — `pytest tests/regression/test_known_defects.py -v` before fix
5. **Passing regression test** — same command after fix applied
6. **GitHub Actions run** — CI workflow screenshot with actual pass/fail status
7. **Architecture diagram** — Mermaid diagram from `docs/architecture.md`
