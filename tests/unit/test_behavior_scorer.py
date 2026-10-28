"""
tests/unit/test_behavior_scorer.py
Unit tests for src/zero_trust/scorer.py

Covers:
  - Unfitted model raises NotFittedError (Requirement 2.5)
  - fit() success and failure paths
  - predict() score range [0, 1] — Property 1
  - Normalisation formula correctness — Property 5
  - Score determinism — Property 6
  - Non-finite input raises ValueError — Requirement 2.8
  - score_detailed() return structure
  - from_pkl() error handling
  - is_fitted / is_pkl_mode properties
  - Threshold constants
"""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sklearn.exceptions import NotFittedError

from src.zero_trust.models import TelemetryVector
from src.zero_trust.scorer import (
    BASELINE_THRESHOLD,
    ESCALATION_THRESHOLD,
    BehaviorScorer,
    _CLAMP_HIGH,
    _CLAMP_LOW,
)

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vec(
    click: list[float] | None = None,
    weights: list[float] | None = None,
    transitions: list[int] | None = None,
    duration: float = 1000.0,
    rate: float = 1.0,
) -> TelemetryVector:
    return TelemetryVector(
        click_speed_intervals=click or [100.0, 200.0, 150.0],
        page_path_weights=weights or [0.3, 0.7],
        sequence_transitions=transitions or [1, 2, 3],
        session_duration_ms=duration,
        request_rate_per_sec=rate,
    )


def _fitted(n: int = 120) -> BehaviorScorer:
    scorer = BehaviorScorer(n_estimators=50, contamination=0.05)
    baseline = [
        _vec(
            click=[float(i % 300 + 50), float(i % 200 + 100)],
            rate=float(i % 10 + 1),
            duration=float(i * 100 + 500),
        )
        for i in range(n)
    ]
    scorer.fit(baseline)
    return scorer


# ===========================================================================
# Unfitted model
# ===========================================================================

class TestUnfittedModel:

    def test_predict_raises_not_fitted(self) -> None:
        with pytest.raises(NotFittedError):
            BehaviorScorer().predict(_vec())

    def test_not_fitted_error_mentions_fit(self) -> None:
        with pytest.raises(NotFittedError, match="fit\\(\\)"):
            BehaviorScorer().predict(_vec())

    def test_is_fitted_false_before_fit(self) -> None:
        assert BehaviorScorer().is_fitted is False

    def test_is_pkl_mode_false_before_fit(self) -> None:
        assert BehaviorScorer().is_pkl_mode is False

    def test_score_detailed_raises_before_fit(self) -> None:
        with pytest.raises(NotFittedError):
            BehaviorScorer().score_detailed(_vec())


# ===========================================================================
# Fitting
# ===========================================================================

class TestFit:

    def test_fit_sets_is_fitted(self) -> None:
        scorer = BehaviorScorer(n_estimators=10)
        scorer.fit([_vec()] * 10)
        assert scorer.is_fitted is True

    def test_fit_sets_pkl_mode_false(self) -> None:
        scorer = BehaviorScorer(n_estimators=10)
        scorer.fit([_vec()] * 10)
        assert scorer.is_pkl_mode is False

    def test_fit_with_10_vectors(self) -> None:
        scorer = BehaviorScorer(n_estimators=10)
        scorer.fit([_vec()] * 10)  # must not raise

    def test_fit_with_invalid_vector_raises(self) -> None:
        scorer = BehaviorScorer(n_estimators=10)
        bad = _vec()
        bad.click_speed_intervals = []  # empty → validation fails
        with pytest.raises(ValueError, match="index 0"):
            scorer.fit([bad])

    def test_fit_accepts_custom_params(self) -> None:
        scorer = BehaviorScorer(n_estimators=20, contamination=0.1)
        scorer.fit([_vec()] * 30)
        assert scorer.is_fitted


# ===========================================================================
# Score range — Property 1
# ===========================================================================

class TestScoreRange:

    def test_normal_vector_in_range(self, fitted_scorer) -> None:
        score = fitted_scorer.predict(_vec())
        assert 0.0 <= score <= 1.0

    def test_anomalous_vector_in_range(self, fitted_scorer) -> None:
        anomalous = _vec(click=[0.001, 0.001], rate=9999.0, duration=50.0)
        score = fitted_scorer.predict(anomalous)
        assert 0.0 <= score <= 1.0

    def test_score_is_float(self, fitted_scorer) -> None:
        assert isinstance(fitted_scorer.predict(_vec()), float)

    @given(
        click=st.lists(st.floats(min_value=0.0, max_value=9000.0, allow_nan=False, allow_infinity=False), min_size=1, max_size=8),
        weights=st.lists(st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False), min_size=1, max_size=5),
        transitions=st.lists(st.integers(min_value=1, max_value=999_999), min_size=1, max_size=5),
        duration=st.floats(min_value=0.0, max_value=86_400_000.0, allow_nan=False, allow_infinity=False),
        rate=st.floats(min_value=0.0, max_value=10_000.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=200, deadline=None)
    def test_prop1_always_bounded(
        self,
        click: list[float],
        weights: list[float],
        transitions: list[int],
        duration: float,
        rate: float,
    ) -> None:
        scorer = _fitted(120)
        vec = TelemetryVector(
            click_speed_intervals=click,
            page_path_weights=weights,
            sequence_transitions=transitions,
            session_duration_ms=duration,
            request_rate_per_sec=rate,
        )
        score = scorer.predict(vec)
        assert 0.0 <= score <= 1.0, f"Score {score} outside [0, 1]"


# ===========================================================================
# Normalisation formula — Property 5
# ===========================================================================

class TestNormalisationFormula:

    def test_raw_minus_half_gives_one(self) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, -0.5))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert score == pytest.approx(1.0)

    def test_raw_plus_half_gives_zero(self) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, 0.5))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert score == pytest.approx(0.0)

    def test_raw_zero_gives_half(self) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, 0.0))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert score == pytest.approx(0.5)

    def test_raw_beyond_clamp_low_clamped(self) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, -999.0))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert score == pytest.approx(1.0)

    def test_raw_beyond_clamp_high_clamped(self) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, 999.0))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert score == pytest.approx(0.0)

    @given(raw=st.floats(min_value=-10.0, max_value=10.0, allow_nan=False, allow_infinity=False))
    @settings(max_examples=300)
    def test_prop5_formula_always_in_range(self, raw: float) -> None:
        clamped = max(_CLAMP_LOW, min(_CLAMP_HIGH, raw))
        score = (_CLAMP_HIGH - clamped) / 1.0
        assert 0.0 <= score <= 1.0


# ===========================================================================
# Score determinism — Property 6
# ===========================================================================

class TestDeterminism:

    def test_same_vector_same_score(self, fitted_scorer) -> None:
        vec = _vec()
        s1 = fitted_scorer.predict(vec)
        s2 = fitted_scorer.predict(vec)
        assert s1 == pytest.approx(s2)

    @given(
        click=st.lists(st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False), min_size=1, max_size=5),
        rate=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=50, deadline=None)
    def test_prop6_deterministic(self, click: list[float], rate: float) -> None:
        scorer = _fitted(100)
        vec = _vec(click=click, rate=rate)
        assert scorer.predict(vec) == pytest.approx(scorer.predict(vec), abs=1e-9)


# ===========================================================================
# Non-finite input — Requirement 2.8
# ===========================================================================

class TestNonFiniteInput:

    def test_nan_click_raises(self, fitted_scorer) -> None:
        with pytest.raises(ValueError):
            fitted_scorer.predict(_vec(click=[float("nan")]))

    def test_inf_click_raises(self, fitted_scorer) -> None:
        with pytest.raises(ValueError):
            fitted_scorer.predict(_vec(click=[float("inf")]))

    def test_neg_inf_click_raises(self, fitted_scorer) -> None:
        with pytest.raises(ValueError):
            fitted_scorer.predict(_vec(click=[float("-inf")]))


# ===========================================================================
# score_detailed()
# ===========================================================================

class TestScoreDetailed:

    def test_returns_dict(self, fitted_scorer) -> None:
        result = fitted_scorer.score_detailed(_vec())
        assert isinstance(result, dict)

    def test_required_keys_present(self, fitted_scorer) -> None:
        result = fitted_scorer.score_detailed(_vec())
        for key in ("anomaly_score", "baseline_threshold", "is_anomaly", "timestamp"):
            assert key in result, f"Missing key: {key}"

    def test_baseline_threshold_is_constant(self, fitted_scorer) -> None:
        result = fitted_scorer.score_detailed(_vec())
        assert result["baseline_threshold"] == pytest.approx(BASELINE_THRESHOLD)

    def test_is_anomaly_consistent_with_score(self, fitted_scorer) -> None:
        result = fitted_scorer.score_detailed(_vec())
        expected = result["anomaly_score"] >= BASELINE_THRESHOLD
        assert result["is_anomaly"] == expected

    def test_timestamp_is_utc_string(self, fitted_scorer) -> None:
        result = fitted_scorer.score_detailed(_vec())
        ts = result["timestamp"]
        assert isinstance(ts, str)
        assert "Z" in ts or "T" in ts  # ISO 8601 UTC

    def test_anomaly_score_rounded(self, fitted_scorer) -> None:
        result = fitted_scorer.score_detailed(_vec())
        # score_detailed() rounds to 6 decimal places
        score = result["anomaly_score"]
        assert score == round(score, 6)

    def test_score_in_range(self, fitted_scorer) -> None:
        result = fitted_scorer.score_detailed(_vec())
        assert 0.0 <= result["anomaly_score"] <= 1.0


# ===========================================================================
# from_pkl() error handling
# ===========================================================================

class TestFromPklErrors:

    def test_missing_pkl_raises_file_not_found(self, tmp_path) -> None:
        from pathlib import Path
        fake_path = tmp_path / "nonexistent_model.pkl"
        with pytest.raises(FileNotFoundError, match="not found"):
            BehaviorScorer.from_pkl(fake_path)

    def test_missing_key_in_bundle_raises_value_error(self, tmp_path) -> None:
        import joblib
        from pathlib import Path
        pkl_path = tmp_path / "bad_bundle.pkl"
        # Bundle missing the 'scaler' key
        joblib.dump({"model": None, "feature_columns": []}, pkl_path)
        with pytest.raises(ValueError, match="missing key"):
            BehaviorScorer.from_pkl(pkl_path)


# ===========================================================================
# Threshold constants
# ===========================================================================

class TestThresholdConstants:

    def test_baseline_threshold_is_0_50(self) -> None:
        assert BASELINE_THRESHOLD == pytest.approx(0.50)

    def test_escalation_threshold_is_0_85(self) -> None:
        assert ESCALATION_THRESHOLD == pytest.approx(0.85)

    def test_escalation_above_baseline(self) -> None:
        assert ESCALATION_THRESHOLD > BASELINE_THRESHOLD
