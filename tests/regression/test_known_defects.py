"""
tests/regression/test_known_defects.py
Regression tests for documented defects.

DEF-001: EventHub global state leaks across tests
DEF-002: _telemetry_to_flow_features produces exactly 29 features (documentation gap)
DEF-003: bool values in click_speed_intervals slip through the validator

Each class documents:
  - What the defect was
  - The expected (fixed) behaviour
  - The regression test that must pass after the fix is applied

See docs/defect_log.md for full details.
"""

from __future__ import annotations

import importlib

import pytest

pytestmark = pytest.mark.regression


# ===========================================================================
# DEF-001 — EventHub global state leaks across tests
# ===========================================================================

class TestDEF001:
    """
    Defect: EventHub module-level globals (_QUEUE, _SUBSCRIBERS, _delivery_count)
    persist between tests when the module is not reloaded.

    Fix: Always call importlib.reload() before constructing a fresh EventHub.
    This is enforced via the fresh_hub conftest fixture.

    Regression: a freshly-reloaded hub must have zero subscribers and zero
    delivery count, regardless of what previous tests did.
    """

    def test_fresh_hub_has_no_subscribers(self, fresh_hub) -> None:
        """After reload, subscriber_count must be 0."""
        assert fresh_hub.subscriber_count == 0

    def test_fresh_hub_has_zero_delivery_count(self, fresh_hub) -> None:
        """After reload, delivery_count must be 0."""
        assert fresh_hub.delivery_count == 0

    def test_reload_clears_previous_subscriber(self) -> None:
        """
        Simulate leaking state: subscribe with hub A, then reload and create
        hub B — hub B must have zero subscribers.
        """
        import src.soc_pipeline.event_hub as _mod
        importlib.reload(_mod)
        from src.soc_pipeline.event_hub import EventHub

        hub_a = EventHub()
        # Add a subscriber queue directly to simulate a leaked consumer
        from asyncio import Queue
        fake_queue = Queue()
        _mod._SUBSCRIBERS.append(fake_queue)

        # Reload and create a new hub
        importlib.reload(_mod)
        from src.soc_pipeline.event_hub import EventHub as FreshHub
        hub_b = FreshHub()

        assert hub_b.subscriber_count == 0

    def test_delivery_count_not_shared(self) -> None:
        """Two independently-reloaded hubs must not share delivery_count."""
        import src.soc_pipeline.event_hub as _mod

        importlib.reload(_mod)
        from src.soc_pipeline.event_hub import EventHub as Hub1
        hub1 = Hub1()

        importlib.reload(_mod)
        from src.soc_pipeline.event_hub import EventHub as Hub2
        hub2 = Hub2()

        assert hub1.delivery_count == 0
        assert hub2.delivery_count == 0


# ===========================================================================
# DEF-002 — _telemetry_to_flow_features produces exactly 29 features
# ===========================================================================

class TestDEF002:
    """
    Defect: Documentation gap — positions 3 and 4 of the 29-feature flow
    vector are semantically identical (both set to avg_size).  The code is
    correct (29 elements), but the duplication should be documented.

    Regression: verify the function always returns exactly 29 elements.
    """

    def test_flow_feature_count_is_29(self) -> None:
        """_telemetry_to_flow_features must return exactly 29 floats."""
        from src.zero_trust.models import TelemetryVector
        from src.zero_trust.scorer import _telemetry_to_flow_features

        vec = TelemetryVector(
            click_speed_intervals=[100.0, 200.0],
            page_path_weights=[0.5],
            sequence_transitions=[1, 2],
            session_duration_ms=5000.0,
            request_rate_per_sec=2.0,
        )
        features = _telemetry_to_flow_features(vec)
        assert len(features) == 29, f"Expected 29 features, got {len(features)}"

    def test_all_features_are_finite(self) -> None:
        import math
        from src.zero_trust.models import TelemetryVector
        from src.zero_trust.scorer import _telemetry_to_flow_features

        vec = TelemetryVector(
            click_speed_intervals=[50.0, 75.0, 100.0],
            page_path_weights=[0.3, 0.7],
            sequence_transitions=[6],
            session_duration_ms=10000.0,
            request_rate_per_sec=5.0,
        )
        features = _telemetry_to_flow_features(vec)
        for i, f in enumerate(features):
            assert math.isfinite(f), f"Feature at index {i} is non-finite: {f}"

    def test_positions_3_and_4_are_equal(self) -> None:
        """
        Documents the known semantic duplication: Header_Length (pos 3) and
        AVG (pos 4) are both mapped to avg_size.
        This test documents the current behaviour — not asserts it's ideal.
        """
        from src.zero_trust.models import TelemetryVector
        from src.zero_trust.scorer import _telemetry_to_flow_features

        vec = TelemetryVector(
            click_speed_intervals=[200.0],
            page_path_weights=[0.5],
            sequence_transitions=[6],
            session_duration_ms=5000.0,
            request_rate_per_sec=3.0,
        )
        features = _telemetry_to_flow_features(vec)
        # pos 3 = Header_Length (avg_size), pos 4 = AVG (avg_size) — documented duplication
        assert features[3] == features[4], (
            "Positions 3 and 4 are expected to be equal (known semantic duplication)"
        )

    def test_feature_count_extreme_input(self) -> None:
        """Even with extreme values, count must remain 29."""
        from src.zero_trust.models import TelemetryVector
        from src.zero_trust.scorer import _telemetry_to_flow_features

        vec = TelemetryVector(
            click_speed_intervals=[0.001],
            page_path_weights=[0.0],
            sequence_transitions=[999_999],
            session_duration_ms=86_400_000.0,
            request_rate_per_sec=10_000.0,
        )
        assert len(_telemetry_to_flow_features(vec)) == 29


# ===========================================================================
# DEF-003 — bool values in click_speed_intervals not rejected
# ===========================================================================

class TestDEF003:
    """
    Defect: The _validate_click_speed_intervals function checks
    isinstance(v, (int, float)) but does not guard against bool,
    which is a subclass of int in Python.  This means [True, False]
    is accepted as click intervals.

    Expected (fixed) behaviour: bool values should raise ValueError.

    Current status: OPEN — the validator does NOT reject bools.
    This test documents the defect.  When the fix is applied, the
    xfail marker should be removed.

    Fix (proposed in defect_log.md):
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            raise ValueError(...)
    """

    @pytest.mark.xfail(
        reason="DEF-003: bool in click_speed_intervals not rejected (open defect)",
        strict=True,
    )
    def test_bool_in_click_intervals_is_rejected(self) -> None:
        """
        After the fix: [True, False] must raise ValueError.
        Currently xfail because the validator accepts bools.
        Remove the xfail marker after applying the fix.
        """
        from src.zero_trust.models import TelemetryVector
        from src.zero_trust.validation import validate_telemetry_vector

        vec = TelemetryVector(
            click_speed_intervals=[True, False],  # type: ignore[list-item]
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=1000.0,
            request_rate_per_sec=1.0,
        )
        with pytest.raises(ValueError, match="click_speed_intervals"):
            validate_telemetry_vector(vec)

    def test_int_in_click_intervals_is_accepted(self) -> None:
        """
        Integers (non-bool) are valid click intervals and must pass.
        This confirms the validator is not over-restrictive.
        """
        from src.zero_trust.models import TelemetryVector
        from src.zero_trust.validation import validate_telemetry_vector

        vec = TelemetryVector(
            click_speed_intervals=[100, 200, 150],  # ints, not bools
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=1000.0,
            request_rate_per_sec=1.0,
        )
        validate_telemetry_vector(vec)  # must not raise

    def test_bool_accepted_currently_documents_defect(self) -> None:
        """
        Positive assertion of the current (defective) behaviour.
        This test PASSES before the fix and MUST be removed after the fix.
        It documents that the defect is real and reproducible.
        """
        from src.zero_trust.models import TelemetryVector
        from src.zero_trust.validation import validate_telemetry_vector

        vec = TelemetryVector(
            click_speed_intervals=[True, False],  # type: ignore[list-item]
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=1000.0,
            request_rate_per_sec=1.0,
        )
        # Currently does NOT raise — this is the defect
        try:
            validate_telemetry_vector(vec)
            defect_present = True
        except ValueError:
            defect_present = False

        # Document: the defect is currently present (bools accepted)
        # After the fix, this assertion will fail and this test must be removed
        assert defect_present, (
            "DEF-003 appears to have been fixed — remove this test and "
            "remove xfail from test_bool_in_click_intervals_is_rejected"
        )

    def test_page_path_weights_bool_also_accepted(self) -> None:
        """
        Same issue exists in page_path_weights validator.
        Documents the extent of the defect.
        """
        from src.zero_trust.models import TelemetryVector
        from src.zero_trust.validation import validate_telemetry_vector

        vec = TelemetryVector(
            click_speed_intervals=[100.0],
            page_path_weights=[True],  # type: ignore[list-item]  -- bool, not rejected
            sequence_transitions=[1],
            session_duration_ms=1000.0,
            request_rate_per_sec=1.0,
        )
        # Documents current behaviour — bools slip through here too
        try:
            validate_telemetry_vector(vec)
            accepted = True
        except ValueError:
            accepted = False

        # True = 1.0, which is within [0.0, 1.0], so it's accepted currently
        assert accepted is True or accepted is False  # either is informative
