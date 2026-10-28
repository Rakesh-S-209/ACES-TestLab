"""
tests/integration/test_soar_pipeline.py
Integration tests for src/soc_pipeline/soar_engine.py

Covers:
  - Property 11: IP blacklisted after trigger_response
  - Property 12: session revoked after trigger_response
  - Property 13: AI_ANOMALY alert published with correct fields
  - Eviction phase < 5 ms
  - Audit log growth
  - Multiple sessions for same IP all revoked
  - Missing session handled gracefully
  - Hypothesis properties 11, 12, 13
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
from src.soc_pipeline.soar_engine import SOAREngine
from src.zero_trust.models import (
    AlertEvent, AlertType, SessionRecord, SessionStatus, SOARResult,
)

pytestmark = pytest.mark.integration


def _session(session_id="s1", ip="203.0.113.5", role="Guest", score=0.9) -> SessionRecord:
    return SessionRecord(session_id=session_id, ip_address=ip, role=role, anomaly_score=score)


def _engine(hub, sessions, blacklist) -> SOAREngine:
    return SOAREngine(
        event_hub=hub,
        active_sessions=sessions,
        perimeter_blacklist=blacklist,
        intel=ThreatIntelAggregator(timeout_s=0.000_001),
    )


# ===========================================================================
# Property 11: IP blacklisted
# ===========================================================================

class TestIPBlacklisted:

    @pytest.mark.asyncio
    async def test_ip_in_blacklist_after_trigger(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["s1"] = _session(ip="203.0.113.5")
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        await eng.trigger_response("203.0.113.5", "s1", 0.92)
        assert "203.0.113.5" in blank_blacklist

    @pytest.mark.asyncio
    async def test_blacklist_persists_across_calls(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["s1"] = _session(ip="203.0.113.6")
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        await eng.trigger_response("203.0.113.6", "s1", 0.9)
        await eng.trigger_response("203.0.113.6", "s1", 0.9)  # second call
        assert "203.0.113.6" in blank_blacklist

    @given(
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
        score=st.floats(min_value=0.76, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=40, deadline=None)
    def test_prop11_ip_always_blacklisted(self, ip: str, score: float) -> None:
        async def _run():
            import importlib
            import src.soc_pipeline.event_hub as _mod
            importlib.reload(_mod)
            from src.soc_pipeline.event_hub import EventHub
            hub = EventHub()
            sessions = {"s1": _session(ip=ip)}
            bl: set = set()
            eng = _engine(hub, sessions, bl)
            await eng.trigger_response(ip, "s1", score)
            assert ip in bl
        asyncio.run(_run())


# ===========================================================================
# Property 12: session revoked
# ===========================================================================

class TestSessionRevoked:

    @pytest.mark.asyncio
    async def test_session_status_revoked(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["s2"] = _session(session_id="s2", ip="203.0.113.7")
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        await eng.trigger_response("203.0.113.7", "s2", 0.88)
        assert blank_sessions["s2"].status is SessionStatus.REVOKED

    @pytest.mark.asyncio
    async def test_revoked_at_ms_set(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["s3"] = _session(session_id="s3", ip="203.0.113.8")
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        before = time.time() * 1000
        await eng.trigger_response("203.0.113.8", "s3", 0.9)
        after = time.time() * 1000
        rec = blank_sessions["s3"]
        assert rec.revoked_at_ms is not None
        assert before <= rec.revoked_at_ms <= after

    @pytest.mark.asyncio
    async def test_all_sessions_for_ip_revoked(
        self, fresh_hub, blank_blacklist
    ) -> None:
        ip = "10.1.1.1"
        sessions = {
            "s1": _session("s1", ip),
            "s2": _session("s2", ip),
            "s3": _session("s3", "10.2.2.2"),
        }
        eng = _engine(fresh_hub, sessions, blank_blacklist)
        eng._revoke_sessions_for_ip(ip)
        assert sessions["s1"].status is SessionStatus.REVOKED
        assert sessions["s2"].status is SessionStatus.REVOKED
        assert sessions["s3"].status is SessionStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_missing_session_no_raise(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        result = await eng.trigger_response("1.2.3.4", "nonexistent", 0.8)
        assert result.success is True

    @given(
        ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True),
        score=st.floats(min_value=0.76, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=40, deadline=None)
    def test_prop12_session_always_revoked(self, ip: str, score: float) -> None:
        async def _run():
            import importlib
            import src.soc_pipeline.event_hub as _mod
            importlib.reload(_mod)
            from src.soc_pipeline.event_hub import EventHub
            hub = EventHub()
            sessions = {"s1": _session(ip=ip)}
            bl: set = set()
            eng = _engine(hub, sessions, bl)
            await eng.trigger_response(ip, "s1", score)
            assert sessions["s1"].status is SessionStatus.REVOKED
        asyncio.run(_run())


# ===========================================================================
# Property 13: AI_ANOMALY alert published
# ===========================================================================

class TestAlertPublished:

    @pytest.mark.asyncio
    async def test_ai_anomaly_alert_published(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["s1"] = _session()
        published: list[AlertEvent] = []
        orig = fresh_hub.publish

        async def capture(e):
            published.append(e)
            await orig(e)

        fresh_hub.publish = capture  # type: ignore[method-assign]
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        await eng.trigger_response("203.0.113.5", "s1", 0.95)
        ai_alerts = [e for e in published if e.alert_type is AlertType.AI_ANOMALY]
        assert len(ai_alerts) == 1
        assert ai_alerts[0].source_ip == "203.0.113.5"
        assert ai_alerts[0].anomaly_score == pytest.approx(0.95)

    @pytest.mark.asyncio
    async def test_alert_has_abuse_score(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["s1"] = _session()
        published: list[AlertEvent] = []
        orig = fresh_hub.publish

        async def capture(e):
            published.append(e)
            await orig(e)

        fresh_hub.publish = capture  # type: ignore[method-assign]
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        await eng.trigger_response("203.0.113.5", "s1", 0.9)
        assert published[0].abuse_score is not None
        assert 0 <= published[0].abuse_score <= 100

    @pytest.mark.asyncio
    async def test_alert_session_id_matches(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["sess-xyz"] = _session(session_id="sess-xyz")
        published: list[AlertEvent] = []
        orig = fresh_hub.publish

        async def capture(e):
            published.append(e)
            await orig(e)

        fresh_hub.publish = capture  # type: ignore[method-assign]
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        await eng.trigger_response("203.0.113.5", "sess-xyz", 0.9)
        assert published[0].session_id == "sess-xyz"


# ===========================================================================
# Eviction timing — Property 13
# ===========================================================================

class TestEvictionTiming:

    @pytest.mark.asyncio
    async def test_eviction_under_5ms(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["s1"] = _session()
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        result = await eng.trigger_response("203.0.113.5", "s1", 0.9)
        assert result.delta_ms is not None
        assert result.delta_ms < 5.0, f"Eviction took {result.delta_ms:.3f} ms"

    @pytest.mark.asyncio
    async def test_result_success_true(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        blank_sessions["s1"] = _session()
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        result = await eng.trigger_response("203.0.113.5", "s1", 0.9)
        assert result.success is True
        assert result.delta_ms >= 0.0

    @given(ip=st.from_regex(r"^(?:\d{1,3}\.){3}\d{1,3}$", fullmatch=True))
    @settings(max_examples=40, deadline=None)
    def test_prop13_eviction_always_under_5ms(self, ip: str) -> None:
        async def _run():
            import importlib
            import src.soc_pipeline.event_hub as _mod
            importlib.reload(_mod)
            from src.soc_pipeline.event_hub import EventHub
            hub = EventHub()
            sessions = {"s1": _session(ip=ip)}
            bl: set = set()
            eng = _engine(hub, sessions, bl)
            return await eng.trigger_response(ip, "s1", 0.9)

        result = asyncio.run(_run())
        assert result.delta_ms is not None
        assert result.delta_ms < 5.0


# ===========================================================================
# Audit log
# ===========================================================================

class TestAuditLog:

    @pytest.mark.asyncio
    async def test_audit_log_starts_empty(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        assert len(eng.audit_log) == 0

    @pytest.mark.asyncio
    async def test_audit_log_grows_per_trigger(
        self, fresh_hub, blank_blacklist
    ) -> None:
        sessions = {
            "s1": _session("s1", "10.0.0.1"),
            "s2": _session("s2", "10.0.0.2"),
        }
        eng = _engine(fresh_hub, sessions, blank_blacklist)
        await eng.trigger_response("10.0.0.1", "s1", 0.8)
        assert len(eng.audit_log) == 1
        await eng.trigger_response("10.0.0.2", "s2", 0.85)
        assert len(eng.audit_log) == 2

    @pytest.mark.asyncio
    async def test_audit_log_is_copy(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        """audit_log property must return a copy, not the internal list."""
        blank_sessions["s1"] = _session()
        eng = _engine(fresh_hub, blank_sessions, blank_blacklist)
        await eng.trigger_response("203.0.113.5", "s1", 0.9)
        log = eng.audit_log
        log.clear()
        assert len(eng.audit_log) == 1  # internal list unaffected
