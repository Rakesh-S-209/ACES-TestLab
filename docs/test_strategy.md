# A.C.E.S. Test Strategy

> Phase 1 deliverable for `ACES-TestLab`.  
> Based on full audit of `Rakesh-S-209/ACES` source code (commit `4c7a1dc`).

---

## 1. Goals

| # | Goal |
|---|---|
| G1 | Verify each detection layer (PortTrap, HoneytokenWatcher, BehaviorScorer) in isolation. |
| G2 | Verify the end-to-end pipeline from event publication to SOC dashboard delivery. |
| G3 | Prevent regressions for every genuine defect discovered during development. |
| G4 | Ensure all tests are repeatable, isolated, and safe on a developer's machine and in CI. |
| G5 | Measure and report code coverage honestly; never inflate figures by excluding real paths. |

---

## 2. Scope

### In scope

- `src/zero_trust/models.py` — all dataclasses and serialisation
- `src/zero_trust/scorer.py` — BehaviorScorer (synthetic-fit mode; pkl mode requires the trained artifact)
- `src/zero_trust/validation.py` — all five field validators
- `src/deception/port_trap.py` — connection handler, alert publication, zero-bytes policy
- `src/deception/token_watcher.py` — event handler filtering, thread-safe bridging
- `src/soc_pipeline/event_hub.py` — publish/subscribe, fan-out, ordering
- `src/soc_pipeline/soar_engine.py` — trigger_response, process_event, session revocation
- `src/soc_pipeline/intel_aggregator.py` — offline fallback, never-raise contract
- `src/portal/gateway.py` — check_web_honeytoken, BasePortalShell.run()
- `src/auth/db.py` — schema init, ban CRUD, session management, event logging

### Out of scope (this phase)

- `run.py` startup orchestrator (integration test; requires all ports)
- `src/soc_pipeline/ws_dashboard.py` — tested via integration tests only (HTTP server)
- `src/portal/financial_shell.py` — covered by quarantine workflow integration tests
- `frontend-aces/` — React SPA; not Python
- AbuseIPDB live API (offline fallback is always used in CI)
- Production `data/behavior_model.pkl` (synthetic fit is used for tests)

---

## 3. Test Levels

### Unit tests
- Fast (< 1 s each), no I/O, no network, no filesystem (beyond `tmp_path`).
- Mock all external I/O: SQLite, filesystem, sockets, AbuseIPDB.
- Targets: models, scorer, validation, event_hub, individual SOAR methods.

### Integration tests
- Involve two or more real components wired together.
- Use temporary SQLite databases (`tmp_path / "test.db"`).
- Use ephemeral high ports (≥ 18000) to avoid privilege issues.
- Targets: quarantine workflow, PortTrap → EventHub → SOAREngine, honeytoken watcher → EventHub.

### Security / negative tests
- Verify rejection of invalid, malformed, or malicious inputs.
- Verify that blocked IPs cannot bypass the gateway.
- Verify that revoked sessions cannot perform authenticated actions.
- Verify that monitor-only mode does not write ban records.
- Never attack external systems; test against the local application only.

### Regression tests
- One test per documented defect.
- Each regression test must fail before the fix and pass after.
- Documented in `docs/defect_log.md`.

---

## 4. Test Isolation Strategy

| Resource | Isolation mechanism |
|---|---|
| SQLite database | `tmp_path / "test.db"` + `auth_db.init_db()` per test |
| EventHub global state | `importlib.reload(_hub_module)` before each hub creation |
| In-memory blacklist | Fresh `set()` per test |
| In-memory sessions | Fresh `dict()` per test |
| watchdog Observer | Started and stopped within test; `tmp_path` directory |
| asyncio event loop | `pytest-asyncio` managed; `asyncio.new_event_loop()` for thread bridging |
| TCP ports | Ephemeral high ports (18000+) allocated per test |
| AbuseIPDB API | `ThreatIntelAggregator(timeout_s=0.000_001)` forces offline fallback |
| Scorer pkl | `BehaviorScorer()` + `scorer.fit(baseline_vectors)` synthetic fit |

---

## 5. Toolchain

| Tool | Version | Role |
|---|---|---|
| `pytest` | ≥ 8.0 | Test runner |
| `pytest-asyncio` | ≥ 0.23 | Async test support (`asyncio_mode = auto`) |
| `pytest-cov` | ≥ 5.0 | Coverage measurement |
| `pytest-html` | ≥ 4.0 | HTML test report |
| `hypothesis` | ≥ 6.100 | Property-based testing (already in requirements.txt) |
| `httpx` | ≥ 0.27 | HTTP integration testing |
| `ruff` | ≥ 0.4 | Linting and formatting checks |
| `unittest.mock` | stdlib | Mocking I/O-bound dependencies |

---

## 6. Markers

```
pytest -m unit           # Fast unit tests only
pytest -m integration    # Integration tests (may open loopback ports)
pytest -m security       # Negative / adversarial input tests
pytest -m regression     # Regression tests for documented defects
pytest -m slow           # Tests that are deliberately slow (Hypothesis deadlines off)
pytest -m "not slow"     # Default CI run excluding slow property tests
```

Marker definitions are in `pytest.ini` (extended in Phase 2).

---

## 7. Coverage Targets

| Module | Baseline (Phase 1) | Target (Phase 8) |
|---|---|---|
| `src/zero_trust/models.py` | ~90% | ≥ 95% |
| `src/zero_trust/scorer.py` | ~80% | ≥ 85% |
| `src/zero_trust/validation.py` | ~95% | ≥ 98% |
| `src/deception/port_trap.py` | ~75% | ≥ 85% |
| `src/deception/token_watcher.py` | ~70% | ≥ 85% |
| `src/soc_pipeline/event_hub.py` | ~85% | ≥ 90% |
| `src/soc_pipeline/soar_engine.py` | ~65% | ≥ 80% |
| `src/soc_pipeline/intel_aggregator.py` | ~75% | ≥ 85% |
| `src/portal/gateway.py` | ~70% | ≥ 80% |
| `src/auth/db.py` | ~50% | ≥ 70% |

Baseline figures are estimates pending first run. Targets will be adjusted after Phase 3 measurement.

---

## 8. CI Strategy

GitHub Actions workflow:
1. `ubuntu-latest`, Python 3.11.
2. Install dependencies from `requirements.txt` + test extras.
3. Run Ruff lint.
4. Run unit tests with coverage.
5. Run integration tests with coverage.
6. Generate JUnit XML + HTML report + coverage HTML.
7. Upload reports as workflow artifacts.
8. Fail on coverage below threshold (set after Phase 3 baseline).

Tests that cannot run in CI:
- Real AbuseIPDB API calls (offline fallback used instead).
- Binding to ports < 1024 (privileged; tests use ephemeral ports).
- `data/behavior_model.pkl` scorer (pkl absent in CI; synthetic fit used).

---

## 9. Known Risks

| Risk | Mitigation |
|---|---|
| EventHub global state leaks between tests | `importlib.reload()` before every hub creation |
| asyncio event loop policy differences (Windows vs Linux) | Use `pytest-asyncio` managed loops |
| Port conflicts on ephemeral test ports | Use wide range (18000–19999); retry logic in fixtures |
| watchdog OS-thread timing in CI | Use `time.sleep()` sparingly; prefer mock-based tests |
| IsolationForest non-determinism | `random_state=42` set; directional assertions only |
| SQLite WAL mode on networked filesystems | Always use `tmp_path` (local disk) |
| Windows SMB port 445 conflict | Never bind 445 in tests; use ephemeral ports |
