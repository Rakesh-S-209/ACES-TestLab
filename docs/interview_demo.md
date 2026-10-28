# ACES-TestLab — SDET Interview Demo Script

> A concise 10-minute walkthrough showing engineering judgement, not just code.

---

## Intro (1 min)

> "I extended a production cybersecurity platform — A.C.E.S. — with a full automated regression suite.
> Before writing a single test, I audited the source code, identified gaps,
> documented three genuine defects, and designed a test architecture that matches
> the system's actual components."

---

## 1. Show the architecture diagram (1 min)

Point to `docs/architecture.md`, section 2 (pipeline diagram):

```
PortTrap → EventHub → SOAREngine → banned_ips (SQLite)
HoneytokenWatcher → EventHub → SOAREngine
BehaviorScorer → EventHub → SOAREngine → PERIMETER_BLACKLIST
```

> "The three detection layers all converge on the EventHub.
> Testing the EventHub in isolation is critical — a broken fan-out would
> silently drop alerts to the SOC dashboard."

---

## 2. Show a genuine defect (2 min)

Open `docs/defect_log.md`, jump to DEF-003:

> "During code review — before running any tests — I found that Python's `bool`
> is a subclass of `int`. The `click_speed_intervals` validator checks
> `isinstance(v, (int, float))`, which returns True for `True` and `False`.
> The scalar validators for `session_duration_ms` have the right guard,
> but the list validator doesn't."

Show the reproduction:
```python
vec = TelemetryVector(
    click_speed_intervals=[True, False],  # bools silently accepted
    ...
)
validate_telemetry_vector(vec)  # does not raise — defect
```

Show `tests/regression/test_known_defects.py::TestDEF003`.

> "The xfail test documents the expected (fixed) behaviour.
> The `test_bool_accepted_currently_documents_defect` test proves the defect is real and reproducible."

---

## 3. Run the unit tests live (2 min)

```bash
cd "PROJECT FOLDER"
pytest tests/unit/ -v --tb=short
```

Expected output: all unit tests pass.

Key test to highlight: `test_prop1_always_bounded` — Hypothesis runs 200 random vectors and asserts the score is always in [0, 1].

> "Property-based testing catches edge cases no manual example would find.
> If the scorer ever produced a score of 1.0000001, this test would catch it."

---

## 4. Show test isolation (1 min)

Open `tests/conftest.py`, point to `fresh_hub` fixture:

```python
@pytest.fixture()
def fresh_hub():
    importlib.reload(_hub_module)  # ← DEF-001 mitigation
    from src.soc_pipeline.event_hub import EventHub
    return EventHub()
```

> "This single line prevents EventHub's module-level globals from leaking
> between tests. Without it, subscriber queues from test A would receive
> events published in test B — a silent, non-deterministic failure."

---

## 5. Show the SOAR pipeline test (1 min)

Open `tests/integration/test_soar_pipeline.py::TestEvictionTiming`:

```python
async def test_eviction_under_5ms(self, ...):
    result = await eng.trigger_response("203.0.113.5", "s1", 0.9)
    assert result.delta_ms < 5.0, f"Eviction took {result.delta_ms:.3f} ms"
```

> "The requirement says memory eviction — blacklist + revoke — must complete
> in under 5 ms. This test measures it. Not a sleep, not a mock — a real
> timing assertion against the actual code path."

---

## 6. Show the CI workflow (1 min)

Open `.github/workflows/ci.yml`:

> "Five jobs: lint → unit → security + integration + regression (parallel) → combined coverage.
> No real AbuseIPDB key. No privileged ports. No production database.
> Every test is isolated and reproducible on any developer machine."

---

## 7. Limitations statement (1 min)

> "I know what this suite cannot do:
> - The production IsolationForest model is not in the repo — pkl-mode is only tested for error handling.
> - The SOCDashboardServer (81 KB) is tested via raw HTTP, not handler unit tests.
> - Port 445 can't be bound on Windows — integration tests use ephemeral ports.
>
> I documented every limitation in `README.md` and `docs/test_strategy.md`.
> Honest coverage reporting is more valuable than a fake 100%."

---

## Key Engineering Decisions to Mention

| Decision | Reasoning |
|---|---|
| `importlib.reload()` in every EventHub fixture | Prevents DEF-001 global state leakage |
| `ThreatIntelAggregator(timeout_s=0.000_001)` in all tests | Forces offline fallback — no live API calls in CI |
| `tmp_path / "test.db"` in every DB test | Production database never touched |
| `@settings(deadline=None)` on slow Hypothesis tests | Prevents DeadlineExceeded on CI |
| `xfail(strict=True)` for DEF-003 | Documents open defect without hiding it |
| Ephemeral ports (18000+) for TCP tests | Avoid Windows port conflicts and privilege requirements |
| Synthetic `scorer.fit()` instead of pkl | Tests run without the 362K-row trained artifact |
