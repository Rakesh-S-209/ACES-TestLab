# Troubleshooting Guide

## Common Failures and Fixes

---

### 1. `ModuleNotFoundError: No module named 'src'`

**Cause**: Tests are run from the wrong directory.

**Fix**: Run pytest from inside `PROJECT FOLDER/` (the directory containing `src/`, `tests/`, and `pytest.ini`):
```bash
cd "PROJECT FOLDER"
pytest
```

---

### 2. `FileNotFoundError: behavior_model.pkl not found`

**Cause**: A test is attempting to use `BehaviorScorer.from_pkl()` without the trained model file present.

**Fix**: All test files must use the synthetic fit path:
```python
scorer = BehaviorScorer(n_estimators=50, contamination=0.05)
scorer.fit(baseline_vectors)
```
The `fitted_scorer` conftest fixture does this automatically.

---

### 3. `OSError: [WinError 10013] An attempt was made to access a socket in a way forbidden`

**Cause**: Windows blocks binding to port 445 (SMB) because the OS `Server` service owns it.

**Fix**: Integration tests must use ephemeral ports. Use the `ephemeral_port` fixture or pick a port in the 18000–19999 range explicitly.  Never use port 445 in tests.

---

### 4. `asyncio.exceptions.CancelledError` during test teardown

**Cause**: An async consumer task is still running when the test ends.

**Fix**: Always `await asyncio.wait_for(task, timeout=N)` or cancel the task in a `finally` block:
```python
task = asyncio.create_task(consumer())
try:
    await asyncio.wait_for(task, timeout=2.0)
finally:
    task.cancel()
```

---

### 5. EventHub tests show stale subscriber counts

**Cause**: Module-level globals (`_SUBSCRIBERS`, `_delivery_count`) from a previous test are still alive (DEF-001).

**Fix**: Use the `fresh_hub` fixture from `conftest.py`. It calls `importlib.reload()` automatically. Never create `EventHub()` directly in a test without reloading.

---

### 6. `hypothesis.errors.DeadlineExceeded`

**Cause**: A Hypothesis test with many examples exceeds the per-example time budget (200 ms default).

**Fix**: Add `@settings(deadline=None)` to slow property-based tests:
```python
@settings(max_examples=100, deadline=None)
def test_property_xxx(self, ...):
    ...
```

---

### 7. Tests pollute the real application database (`aces_production.db`)

**Cause**: `auth_db.init_db()` was called without a path argument, defaulting to `data/aces_production.db`.

**Fix**: Always use the `tmp_db` fixture:
```python
def test_something(self, tmp_db) -> None:
    from src.auth import db as auth_db
    # tmp_db is a Path — auth_db is already initialised at that path
    ...
```

---

### 8. `pytest-asyncio` deprecation warning about `asyncio_mode`

**Cause**: Old `pytest-asyncio` version before `asyncio_mode = auto` was added.

**Fix**: Pin `pytest-asyncio>=0.23.0` as specified in `requirements.txt`.

---

### 9. `NotFittedError` when calling `scorer.predict()` in tests

**Cause**: `BehaviorScorer()` was constructed but `fit()` was never called.

**Fix**: Use the `fitted_scorer` fixture or call `scorer.fit(baseline)` explicitly before `predict()`.

---

### 10. Integration tests fail with `ConnectionRefusedError`

**Cause**: The ephemeral port chosen by `ephemeral_port` fixture was taken between allocation and bind.

**Fix**: This is a TOCTOU window on busy systems. Re-run the test. If it fails consistently, pick a different port range or retry with a loop:
```python
import socket
for port in range(18000, 19000):
    try:
        s = socket.socket()
        s.bind(("127.0.0.1", port))
        s.close()
        break
    except OSError:
        continue
```

---

## Running Specific Test Groups

```bash
# Only fast unit tests
pytest -m unit -v

# Only security tests  
pytest -m security -v

# Only regression tests (includes xfail for DEF-003)
pytest -m regression -v

# Everything except slow Hypothesis tests
pytest -m "not slow" -v

# Single test file
pytest tests/unit/test_behavior_scorer.py -v

# Single test class
pytest tests/integration/test_soar_pipeline.py::TestIPBlacklisted -v

# With coverage
pytest --cov=src --cov-report=term-missing -m unit
```

---

## Environment Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11 | Match upstream requirement |
| pytest | ≥ 8.0 | From requirements.txt |
| pytest-asyncio | ≥ 0.23 | `asyncio_mode = auto` |
| scikit-learn | ≥ 1.4.0 | IsolationForest |
| watchdog | ≥ 4.0.0 | HoneytokenWatcher |
| hypothesis | ≥ 6.100 | Property-based tests |
| httpx | ≥ 0.27 | HTTP integration tests |
| pytest-cov | ≥ 5.0 | Coverage |
| pytest-html | ≥ 4.1 | HTML report |
| ruff | ≥ 0.4 | Linting |
