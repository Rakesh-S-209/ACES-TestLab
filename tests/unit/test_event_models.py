"""
tests/unit/test_event_models.py
Unit tests for src/zero_trust/models.py

Covers:
  - TelemetryVector.to_feature_array() — shape, type, finiteness
  - SessionRecord — lifecycle, revocation_delta_ms property
  - AlertEvent — to_json() serialisation, required fields, None exclusion
  - Supporting models — GatewayDecision, SOARResult, IPReputationReport
  - Hypothesis properties 8, 9, 10, 24, 25, 26
"""

from __future__ import annotations

import math
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.zero_trust.models import (
    AlertEvent,
    AlertType,
    GatewayDecision,
    IPReputationReport,
    PolicyAction,
    SOARResult,
    SessionRecord,
    SessionStatus,
    TelemetryVector,
)

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Hypothesis strategies (reusable)
# ---------------------------------------------------------------------------

_unit_floats = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
_valid_tv = st.builds(
    TelemetryVector,
    click_speed_intervals=st.lists(
        st.floats(min_value=0.0, max_value=9000.0, allow_nan=False, allow_infinity=False),
        min_size=1, max_size=10,
    ),
    page_path_weights=st.lists(_unit_floats, min_size=1, max_size=10),
    sequence_transitions=st.lists(st.integers(min_value=1, max_value=999_999), min_size=1, max_size=10),
    session_duration_ms=st.floats(min_value=0.0, max_value=86_400_000.0, allow_nan=False, allow_infinity=False),
    request_rate_per_sec=st.floats(min_value=0.0, max_value=10_000.0, allow_nan=False, allow_infinity=False),
)


# ===========================================================================
# TelemetryVector
# ===========================================================================

class TestTelemetryVector:

    def _valid(self) -> TelemetryVector:
        return TelemetryVector(
            click_speed_intervals=[100.0, 200.0, 150.0],
            page_path_weights=[0.3, 0.7],
            sequence_transitions=[1, 2, 3],
            session_duration_ms=5000.0,
            request_rate_per_sec=2.5,
        )

    # ── Shape and type ───────────────────────────────────────────────────────

    def test_feature_array_returns_list(self) -> None:
        result = self._valid().to_feature_array()
        assert isinstance(result, list)

    def test_feature_array_length_is_11(self) -> None:
        result = self._valid().to_feature_array()
        assert len(result) == TelemetryVector._FEATURE_DIM == 11

    def test_feature_array_all_floats(self) -> None:
        for v in self._valid().to_feature_array():
            assert isinstance(v, float)

    def test_feature_array_all_finite(self) -> None:
        for v in self._valid().to_feature_array():
            assert math.isfinite(v), f"Non-finite value: {v}"

    # ── Element correctness ──────────────────────────────────────────────────

    def test_session_duration_at_index_9(self) -> None:
        vec = TelemetryVector(
            click_speed_intervals=[100.0],
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=12345.0,
            request_rate_per_sec=0.0,
        )
        fa = vec.to_feature_array()
        assert fa[9] == 12345.0

    def test_request_rate_at_index_10(self) -> None:
        vec = TelemetryVector(
            click_speed_intervals=[100.0],
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=0.0,
            request_rate_per_sec=7.5,
        )
        fa = vec.to_feature_array()
        assert fa[10] == 7.5

    def test_empty_click_intervals_summarise_to_zeros(self) -> None:
        """Empty list → mean=0, max=0, count=0 at indices 0–2."""
        vec = TelemetryVector(
            click_speed_intervals=[],  # empty is allowed here (validation rejects it, model doesn't)
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=0.0,
            request_rate_per_sec=0.0,
        )
        fa = vec.to_feature_array()
        assert fa[0] == 0.0  # mean
        assert fa[1] == 0.0  # max
        assert fa[2] == 0.0  # count

    # ── NaN / Inf guards ─────────────────────────────────────────────────────

    def test_nan_in_click_intervals_raises(self) -> None:
        vec = TelemetryVector(
            click_speed_intervals=[float("nan")],
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=0.0,
            request_rate_per_sec=0.0,
        )
        with pytest.raises(ValueError, match="non-finite"):
            vec.to_feature_array()

    def test_inf_in_click_intervals_raises(self) -> None:
        vec = TelemetryVector(
            click_speed_intervals=[float("inf")],
            page_path_weights=[0.5],
            sequence_transitions=[1],
            session_duration_ms=0.0,
            request_rate_per_sec=0.0,
        )
        with pytest.raises(ValueError, match="non-finite"):
            vec.to_feature_array()

    # ── Property 8 ───────────────────────────────────────────────────────────

    @given(_valid_tv)
    @settings(max_examples=200)
    def test_prop8_always_finite(self, vec: TelemetryVector) -> None:
        result = vec.to_feature_array()
        assert len(result) > 0
        for v in result:
            assert math.isfinite(v), f"Non-finite: {v}"


# ===========================================================================
# SessionRecord
# ===========================================================================

class TestSessionRecord:

    def _active(self) -> SessionRecord:
        return SessionRecord(
            session_id="sess-001",
            ip_address="192.168.1.1",
            role="Guest",
            anomaly_score=0.3,
        )

    def test_default_status_active(self) -> None:
        assert self._active().status is SessionStatus.ACTIVE

    def test_revoked_at_ms_none_by_default(self) -> None:
        assert self._active().revoked_at_ms is None

    def test_delta_none_when_active(self) -> None:
        assert self._active().revocation_delta_ms is None

    def test_delta_none_when_expired(self) -> None:
        rec = self._active()
        rec.status = SessionStatus.EXPIRED
        assert rec.revocation_delta_ms is None

    def test_delta_computed_correctly(self) -> None:
        created = time.time() * 1000
        rec = SessionRecord(
            session_id="s",
            ip_address="10.0.0.1",
            role="Admin",
            anomaly_score=0.9,
            status=SessionStatus.REVOKED,
            created_at_ms=created,
            revoked_at_ms=created + 1500.0,
        )
        assert rec.revocation_delta_ms == pytest.approx(1500.0)

    def test_delta_non_negative(self) -> None:
        now = time.time() * 1000
        rec = SessionRecord(
            session_id="s",
            ip_address="10.0.0.2",
            role="Engineer",
            anomaly_score=0.8,
            status=SessionStatus.REVOKED,
            created_at_ms=now,
            revoked_at_ms=now,  # zero elapsed
        )
        assert rec.revocation_delta_ms == pytest.approx(0.0)
        assert rec.revocation_delta_ms >= 0.0

    def test_created_at_ms_auto_populated(self) -> None:
        before = time.time() * 1000
        rec = self._active()
        after = time.time() * 1000
        assert before <= rec.created_at_ms <= after

    # ── Property 9 ───────────────────────────────────────────────────────────

    @given(
        session_id=st.text(min_size=1, max_size=64),
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
        role=st.sampled_from(["Admin", "Engineer", "Guest"]),
        score=_unit_floats,
    )
    @settings(max_examples=150)
    def test_prop9_required_fields_always_present(
        self, session_id: str, ip: str, role: str, score: float
    ) -> None:
        rec = SessionRecord(session_id=session_id, ip_address=ip, role=role, anomaly_score=score)
        assert rec.session_id is not None
        assert rec.ip_address is not None
        assert rec.role is not None
        assert rec.anomaly_score is not None
        assert rec.status is SessionStatus.ACTIVE

    # ── Property 10 ──────────────────────────────────────────────────────────

    @given(
        created=st.floats(min_value=0.0, max_value=1e10, allow_nan=False, allow_infinity=False),
        elapsed=st.floats(min_value=0.0, max_value=1e6, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=150)
    def test_prop10_delta_correct(self, created: float, elapsed: float) -> None:
        rec = SessionRecord(
            session_id="s",
            ip_address="1.2.3.4",
            role="Guest",
            anomaly_score=0.5,
            status=SessionStatus.REVOKED,
            created_at_ms=created,
            revoked_at_ms=created + elapsed,
        )
        delta = rec.revocation_delta_ms
        assert delta is not None
        assert delta == pytest.approx(elapsed, rel=1e-6, abs=1e-3)
        assert delta >= 0.0


# ===========================================================================
# AlertEvent
# ===========================================================================

class TestAlertEvent:

    def _ai(self) -> AlertEvent:
        return AlertEvent(
            alert_type=AlertType.AI_ANOMALY,
            source_ip="203.0.113.5",
            timestamp_ms=1_700_000_000_000.0,
            session_id="s1",
            anomaly_score=0.88,
            abuse_score=95,
            revocation_delta_ms=350.0,
        )

    def _honeytoken(self) -> AlertEvent:
        return AlertEvent(
            alert_type=AlertType.HONEYTOKEN_ACCESS,
            source_ip="local",
            timestamp_ms=1_700_000_001_000.0,
            affected_path="/abs/data/honey_tokens/db_config.json",
        )

    def _port_trap(self) -> AlertEvent:
        return AlertEvent(
            alert_type=AlertType.PORT_TRAP,
            source_ip="198.51.100.42",
            timestamp_ms=1_700_000_002_000.0,
            port=3389,
        )

    # ── Property 25: required fields always present ───────────────────────────

    def test_required_fields_in_json(self) -> None:
        for evt in [self._ai(), self._honeytoken(), self._port_trap()]:
            payload = evt.to_json()
            assert "alert_type" in payload
            assert "source_ip" in payload
            assert "timestamp_ms" in payload

    def test_alert_type_is_string_in_json(self) -> None:
        payload = self._ai().to_json()
        assert isinstance(payload["alert_type"], str)
        assert payload["alert_type"] == "AI_ANOMALY"

    # ── None fields excluded ─────────────────────────────────────────────────

    def test_none_fields_excluded_from_json(self) -> None:
        evt = AlertEvent(
            alert_type=AlertType.PORT_TRAP,
            source_ip="1.2.3.4",
            timestamp_ms=0.0,
            port=3389,
        )
        payload = evt.to_json()
        assert "session_id" not in payload
        assert "anomaly_score" not in payload
        assert "affected_path" not in payload
        assert "abuse_score" not in payload
        assert "revocation_delta_ms" not in payload

    # ── Port trap specific ───────────────────────────────────────────────────

    def test_port_trap_port_in_json(self) -> None:
        payload = self._port_trap().to_json()
        assert payload["port"] == 3389

    # ── Honeytoken specific ──────────────────────────────────────────────────

    def test_honeytoken_path_in_json(self) -> None:
        payload = self._honeytoken().to_json()
        assert "affected_path" in payload

    # ── Property 26: AI_ANOMALY enrichment fields ────────────────────────────

    def test_ai_enrichment_fields_non_none(self) -> None:
        evt = self._ai()
        assert evt.session_id is not None
        assert evt.anomaly_score is not None
        assert evt.abuse_score is not None
        assert evt.revocation_delta_ms is not None

    # ── Property 24: round-trip serialisation ────────────────────────────────

    def test_round_trip_ai_anomaly(self) -> None:
        original = self._ai()
        payload = original.to_json()
        restored = AlertEvent(
            alert_type=AlertType(payload["alert_type"]),
            source_ip=payload["source_ip"],
            timestamp_ms=payload["timestamp_ms"],
            session_id=payload.get("session_id"),
            anomaly_score=payload.get("anomaly_score"),
            abuse_score=payload.get("abuse_score"),
            revocation_delta_ms=payload.get("revocation_delta_ms"),
        )
        assert restored.alert_type == original.alert_type
        assert restored.source_ip == original.source_ip
        assert restored.session_id == original.session_id
        assert restored.anomaly_score == pytest.approx(original.anomaly_score)  # type: ignore[arg-type]
        assert restored.abuse_score == original.abuse_score

    def test_round_trip_port_trap(self) -> None:
        original = self._port_trap()
        payload = original.to_json()
        restored = AlertEvent(
            alert_type=AlertType(payload["alert_type"]),
            source_ip=payload["source_ip"],
            timestamp_ms=payload["timestamp_ms"],
            port=payload.get("port"),
        )
        assert restored.port == 3389


# ===========================================================================
# Supporting models
# ===========================================================================

class TestSupportingModels:

    def test_ip_reputation_report(self) -> None:
        r = IPReputationReport(
            ip_address="1.2.3.4",
            abuse_confidence_score=75,
            country_code="US",
            total_reports=12,
            is_whitelisted=False,
            source="abuseipdb",
        )
        assert r.source == "abuseipdb"
        assert 0 <= r.abuse_confidence_score <= 100

    def test_gateway_decision_block(self) -> None:
        d = GatewayDecision(
            action=PolicyAction.BLOCK,
            session_id=None,
            anomaly_score=0.0,
            reason="blacklisted_ip",
        )
        assert d.action is PolicyAction.BLOCK
        assert d.session_id is None

    def test_soar_result(self) -> None:
        r = SOARResult(success=True, delta_ms=500.0)
        assert r.success is True
        assert r.delta_ms == pytest.approx(500.0)

    def test_policy_action_enum_values(self) -> None:
        assert PolicyAction.ALLOW.value == "ALLOW"
        assert PolicyAction.BLOCK.value == "BLOCK"
        assert PolicyAction.REVOKE.value == "REVOKE"

    def test_alert_type_enum_values(self) -> None:
        assert AlertType.AI_ANOMALY.value == "AI_ANOMALY"
        assert AlertType.HONEYTOKEN_ACCESS.value == "HONEYTOKEN_ACCESS"
        assert AlertType.PORT_TRAP.value == "PORT_TRAP"

    def test_session_status_enum_values(self) -> None:
        assert SessionStatus.ACTIVE.value == "ACTIVE"
        assert SessionStatus.REVOKED.value == "REVOKED"
        assert SessionStatus.EXPIRED.value == "EXPIRED"
