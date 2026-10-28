# A.C.E.S. Defect Log

> Updated progressively throughout Phases 1–6.  
> Only genuine defects discovered during code review or test execution are recorded here.  
> Fabricated defects are not acceptable.

---

## Format

Each entry follows this template:

```
### DEF-NNN — <Short Title>

**Status**: Open | Fixed | Won't Fix  
**Severity**: Critical | High | Medium | Low  
**Component**: src/...  
**Discovered**: Phase N / <method>

#### Expected behaviour
...

#### Actual behaviour
...

#### Root cause
...

#### Reproduction
```python
# minimal reproduction
```

#### Fix
...

#### Regression test
`tests/regression/test_known_defects.py::TestDEFNNN::...`
```

---

## Defects Discovered in Phase 1 (Code Review)

### DEF-001 — EventHub Global State Leaks Across Tests

**Status**: Documented (by design — acknowledged upstream)  
**Severity**: Medium  
**Component**: `src/soc_pipeline/event_hub.py`  
**Discovered**: Phase 1 / static code review

#### Expected behaviour
Each test should start with a clean EventHub — zero subscribers, empty delivery count.

#### Actual behaviour
`_QUEUE`, `_SUBSCRIBERS`, and `_delivery_count` are module-level globals. Any test that creates an `EventHub` without reloading the module will see state left by a previous test. Subscriber queues from one test can receive events published by a later test.

#### Root cause
The EventHub uses module-level singletons to allow the `get_queue()` method to return a stable reference for `call_soon_threadsafe` bridging from OS threads. This is correct for production (one process, one loop) but problematic for tests (many tests, one process).

#### Reproduction
```python
import src.soc_pipeline.event_hub as _mod
from src.soc_pipeline.event_hub import EventHub

hub1 = EventHub()
# subscribe but never consume

hub2 = EventHub()  # same module globals — subscriber from hub1 is still registered
```

#### Fix
All test files that create an `EventHub` must call `importlib.reload(_hub_module)` first. This is already done in the existing upstream tests. The ACES-TestLab `conftest.py` will enforce this via a fixture.

#### Regression test
`tests/regression/test_known_defects.py::TestDEF001::test_fresh_hub_has_no_subscribers`

---

### DEF-002 — `_telemetry_to_flow_features` Produces 29 Values But Column Comment Lists 29 — Off-by-One in Documentation

**Status**: Documentation gap (code is correct)  
**Severity**: Low  
**Component**: `src/zero_trust/scorer.py`  
**Discovered**: Phase 1 / code review of `_telemetry_to_flow_features()`

#### Expected behaviour
The function docstring states 29 features in `_PKL_FEATURE_COLUMNS`. The actual `return` list should also have 29 elements.

#### Actual behaviour
Counting the elements in the `return [...]` statement:
```
rate, iat, variance,              # 3
avg_size, avg_size, std_size, tot_size, min_size, max_size,   # 6 (index 3–8)
number, ttl, proto,               # 3 (index 9–11)
fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, ece_flag, cwr_flag,  # 7 (index 12–18)
syn_count, fin_count, rst_count, ack_count,   # 4 (index 19–22)
tcp_frac, udp_frac, http_frac, https_frac, dns_frac, icmp_frac,  # 6 (index 23–28)
```
Total = 3 + 6 + 3 + 7 + 4 + 6 = **29** ✅

However, `_PKL_FEATURE_COLUMNS` maps `"Header_Length"` and `"AVG"` to positions [3] and [4] respectively, both of which are set to `avg_size` — identical values. This means feature `Header_Length` (index 3) and `AVG` (index 4) will always be the same value in the pkl-mode path. This is a semantic duplication, not a count error.

#### Root cause
The feature bridge maps a portal-level `TelemetryVector` (5 fields) to a network-flow feature space (29 fields). The mapping is inherently lossy and approximate. The semantic duplication is acknowledged and does not cause inference errors.

#### Fix
Add a comment in `_telemetry_to_flow_features()` explicitly noting that positions [3] and [4] are intentionally identical in the portal-to-flow mapping. No code change required.

#### Regression test
`tests/regression/test_known_defects.py::TestDEF002::test_flow_feature_count_is_29`

---

### DEF-003 — `validate_telemetry_vector` Calls `to_feature_array()` as Final Guard, But `to_feature_array()` Does Not Validate Types — Bool Slips Through

**Status**: Open  
**Severity**: Medium  
**Component**: `src/zero_trust/validation.py`, `src/zero_trust/models.py`  
**Discovered**: Phase 1 / code review

#### Expected behaviour
Passing `True` (Python `bool`) as `session_duration_ms` should raise `ValueError` with a message about type mismatch.

#### Actual behaviour
The `_validate_session_duration_ms` validator explicitly checks:
```python
if not isinstance(value, (int, float)) or isinstance(value, bool):
    raise ValueError(...)
```
This correctly rejects `True`.

However, `_validate_click_speed_intervals` checks `isinstance(v, (int, float))`. In Python, `bool` is a subclass of `int`, so `isinstance(True, (int, float))` returns `True`. The validator does **not** check `isinstance(v, bool)` for individual list elements in `click_speed_intervals`. This means `[True, False]` is accepted as a valid click interval list.

#### Root cause
`bool` is a subclass of `int` in Python. The scalar validators for `session_duration_ms` and `request_rate_per_sec` correctly guard against `bool` with an explicit `isinstance(value, bool)` check. The list-element validator in `_validate_click_speed_intervals` does not have this guard.

The practical impact is low: `True` = 1.0 ms and `False` = 0.0 ms are valid interval values numerically. However, the inconsistency is a design smell and could allow silent type confusion.

#### Reproduction
```python
from src.zero_trust.models import TelemetryVector
from src.zero_trust.validation import validate_telemetry_vector

vec = TelemetryVector(
    click_speed_intervals=[True, False],   # bools slip through
    page_path_weights=[0.5],
    sequence_transitions=[1],
    session_duration_ms=1000.0,
    request_rate_per_sec=1.0,
)
validate_telemetry_vector(vec)  # does not raise — bools accepted
```

#### Fix (proposed)
Add `or isinstance(v, bool)` guard to the type check in `_validate_click_speed_intervals`:
```python
if not isinstance(v, (int, float)) or isinstance(v, bool):
    raise ValueError(...)
```
Apply the same fix to `_validate_page_path_weights`.

#### Regression test
`tests/regression/test_known_defects.py::TestDEF003::test_bool_in_click_intervals_is_rejected`

---

## Defects Discovered in Phases 2–6

*(To be added as tests are written and executed.)*

---

## Defect Summary

| ID | Title | Severity | Status |
|---|---|---|---|
| DEF-001 | EventHub global state leaks across tests | Medium | Documented |
| DEF-002 | `_telemetry_to_flow_features` semantic duplication at positions 3 and 4 | Low | Documentation gap |
| DEF-003 | `bool` values in `click_speed_intervals` not rejected by validator | Medium | Open |
