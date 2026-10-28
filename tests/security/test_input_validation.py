"""
tests/security/test_input_validation.py
Security tests for src/zero_trust/validation.py

Covers Property 7: validation always rejects any out-of-range or malformed input
before ML scoring is attempted.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.zero_trust.models import TelemetryVector
from src.zero_trust.validation import validate_telemetry_vector

pytestmark = pytest.mark.security


def _valid() -> TelemetryVector:
    return TelemetryVector(
        click_speed_intervals=[100.0, 200.0],
        page_path_weights=[0.5, 0.8],
        sequence_transitions=[1, 2, 3],
        session_duration_ms=3000.0,
        request_rate_per_sec=5.0,
    )


# ===========================================================================
# click_speed_intervals
# ===========================================================================

class TestClickSpeedIntervals:

    def test_empty_raises(self) -> None:
        v = _valid(); v.click_speed_intervals = []
        with pytest.raises(ValueError, match="click_speed_intervals"):
            validate_telemetry_vector(v)

    def test_over_max_length_raises(self) -> None:
        v = _valid(); v.click_speed_intervals = [1.0] * 1001
        with pytest.raises(ValueError, match="click_speed_intervals"):
            validate_telemetry_vector(v)

    def test_exactly_max_length_passes(self) -> None:
        v = _valid(); v.click_speed_intervals = [0.0] * 1000
        validate_telemetry_vector(v)  # must not raise

    def test_negative_value_raises(self) -> None:
        v = _valid(); v.click_speed_intervals = [100.0, -1.0]
        with pytest.raises(ValueError, match="click_speed_intervals"):
            validate_telemetry_vector(v)

    def test_zero_passes(self) -> None:
        v = _valid(); v.click_speed_intervals = [0.0]
        validate_telemetry_vector(v)

    def test_nan_raises(self) -> None:
        v = _valid(); v.click_speed_intervals = [float("nan")]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    def test_inf_raises(self) -> None:
        v = _valid(); v.click_speed_intervals = [float("inf")]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    def test_neg_inf_raises(self) -> None:
        v = _valid(); v.click_speed_intervals = [float("-inf")]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    def test_non_list_raises(self) -> None:
        v = _valid(); v.click_speed_intervals = "not_a_list"  # type: ignore[assignment]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    @given(bad=st.floats(max_value=-0.001, allow_nan=False, allow_infinity=False))
    @settings(max_examples=100)
    def test_prop7_negative_always_rejected(self, bad: float) -> None:
        v = _valid(); v.click_speed_intervals = [bad]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)


# ===========================================================================
# page_path_weights
# ===========================================================================

class TestPagePathWeights:

    def test_empty_raises(self) -> None:
        v = _valid(); v.page_path_weights = []
        with pytest.raises(ValueError, match="page_path_weights"):
            validate_telemetry_vector(v)

    def test_above_one_raises(self) -> None:
        v = _valid(); v.page_path_weights = [1.1]
        with pytest.raises(ValueError, match="page_path_weights"):
            validate_telemetry_vector(v)

    def test_below_zero_raises(self) -> None:
        v = _valid(); v.page_path_weights = [-0.1]
        with pytest.raises(ValueError, match="page_path_weights"):
            validate_telemetry_vector(v)

    def test_boundary_zero_passes(self) -> None:
        v = _valid(); v.page_path_weights = [0.0]
        validate_telemetry_vector(v)

    def test_boundary_one_passes(self) -> None:
        v = _valid(); v.page_path_weights = [1.0]
        validate_telemetry_vector(v)

    def test_nan_weight_raises(self) -> None:
        v = _valid(); v.page_path_weights = [float("nan")]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    @given(bad=st.one_of(
        st.floats(max_value=-0.001, allow_nan=False, allow_infinity=False),
        st.floats(min_value=1.001, allow_nan=False, allow_infinity=False),
    ))
    @settings(max_examples=100)
    def test_prop7_out_of_range_always_rejected(self, bad: float) -> None:
        v = _valid(); v.page_path_weights = [bad]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)


# ===========================================================================
# sequence_transitions
# ===========================================================================

class TestSequenceTransitions:

    def test_zero_raises(self) -> None:
        v = _valid(); v.sequence_transitions = [0]
        with pytest.raises(ValueError, match="sequence_transitions"):
            validate_telemetry_vector(v)

    def test_above_max_raises(self) -> None:
        v = _valid(); v.sequence_transitions = [1_000_000]
        with pytest.raises(ValueError, match="sequence_transitions"):
            validate_telemetry_vector(v)

    def test_boundary_min_passes(self) -> None:
        v = _valid(); v.sequence_transitions = [1]
        validate_telemetry_vector(v)

    def test_boundary_max_passes(self) -> None:
        v = _valid(); v.sequence_transitions = [999_999]
        validate_telemetry_vector(v)

    def test_float_in_list_raises(self) -> None:
        v = _valid(); v.sequence_transitions = [1.5]  # type: ignore[list-item]
        with pytest.raises(ValueError, match="sequence_transitions"):
            validate_telemetry_vector(v)

    def test_bool_in_list_raises(self) -> None:
        """bool is a subclass of int — explicit check needed."""
        v = _valid(); v.sequence_transitions = [True]  # type: ignore[list-item]
        with pytest.raises(ValueError, match="sequence_transitions"):
            validate_telemetry_vector(v)

    def test_string_in_list_raises(self) -> None:
        v = _valid(); v.sequence_transitions = ["1"]  # type: ignore[list-item]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    def test_empty_list_passes(self) -> None:
        """Empty sequence is allowed — nothing to validate."""
        v = _valid(); v.sequence_transitions = []
        validate_telemetry_vector(v)


# ===========================================================================
# session_duration_ms
# ===========================================================================

class TestSessionDurationMs:

    def test_negative_raises(self) -> None:
        v = _valid(); v.session_duration_ms = -1.0
        with pytest.raises(ValueError, match="session_duration_ms"):
            validate_telemetry_vector(v)

    def test_exceeds_24h_raises(self) -> None:
        v = _valid(); v.session_duration_ms = 86_400_001.0
        with pytest.raises(ValueError, match="session_duration_ms"):
            validate_telemetry_vector(v)

    def test_exactly_24h_passes(self) -> None:
        v = _valid(); v.session_duration_ms = 86_400_000.0
        validate_telemetry_vector(v)

    def test_zero_passes(self) -> None:
        v = _valid(); v.session_duration_ms = 0.0
        validate_telemetry_vector(v)

    def test_nan_raises(self) -> None:
        v = _valid(); v.session_duration_ms = float("nan")
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    def test_bool_raises(self) -> None:
        v = _valid(); v.session_duration_ms = True  # type: ignore[assignment]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    def test_string_raises(self) -> None:
        v = _valid(); v.session_duration_ms = "1000"  # type: ignore[assignment]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    @given(bad=st.floats(max_value=-0.001, allow_nan=False, allow_infinity=False))
    @settings(max_examples=100)
    def test_prop7_negative_always_rejected(self, bad: float) -> None:
        v = _valid(); v.session_duration_ms = bad
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)


# ===========================================================================
# request_rate_per_sec
# ===========================================================================

class TestRequestRatePerSec:

    def test_negative_raises(self) -> None:
        v = _valid(); v.request_rate_per_sec = -0.1
        with pytest.raises(ValueError, match="request_rate_per_sec"):
            validate_telemetry_vector(v)

    def test_exceeds_max_raises(self) -> None:
        v = _valid(); v.request_rate_per_sec = 10_001.0
        with pytest.raises(ValueError, match="request_rate_per_sec"):
            validate_telemetry_vector(v)

    def test_exactly_max_passes(self) -> None:
        v = _valid(); v.request_rate_per_sec = 10_000.0
        validate_telemetry_vector(v)

    def test_zero_passes(self) -> None:
        v = _valid(); v.request_rate_per_sec = 0.0
        validate_telemetry_vector(v)

    def test_bool_raises(self) -> None:
        v = _valid(); v.request_rate_per_sec = False  # type: ignore[assignment]
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    def test_nan_raises(self) -> None:
        v = _valid(); v.request_rate_per_sec = float("nan")
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)

    @given(bad=st.floats(max_value=-0.001, allow_nan=False, allow_infinity=False))
    @settings(max_examples=100)
    def test_prop7_negative_rate_always_rejected(self, bad: float) -> None:
        v = _valid(); v.request_rate_per_sec = bad
        with pytest.raises(ValueError):
            validate_telemetry_vector(v)


# ===========================================================================
# Cross-field: valid vector passes all checks
# ===========================================================================

class TestValidVectorPasses:

    @pytest.mark.parametrize("rate", [0.0, 1.0, 100.0, 10_000.0])
    def test_various_valid_rates(self, rate: float) -> None:
        v = _valid(); v.request_rate_per_sec = rate
        validate_telemetry_vector(v)

    @pytest.mark.parametrize("duration", [0.0, 1000.0, 86_400_000.0])
    def test_various_valid_durations(self, duration: float) -> None:
        v = _valid(); v.session_duration_ms = duration
        validate_telemetry_vector(v)
