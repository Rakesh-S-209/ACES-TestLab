"""
tests/integration/test_session_revocation.py
Integration tests for session lifecycle and revocation.

Covers:
  - SOAR revokes sessions in-memory and in SQLite
  - revocation_delta_ms is computed correctly
  - Multiple sessions for the same IP all revoked
  - Already-revoked session not double-counted
  - Session status transitions ACTIVE → REVOKED
"""

from __future__ import annotations

import time

import pytest

from src.zero_trust.models import SessionRecord, SessionStatus

pytestmark = pytest.mark.integration


class TestSessionRevocationIntegration:

    @pytest.mark.asyncio
    async def test_soar_revokes_in_memory_session(
        self, fresh_hub, blank_blacklist, tmp_db
    ) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine

        ip = "203.0.113.20"
        sessions = {
            "s1": SessionRecord(session_id="s1", ip_address=ip, role="Guest", anomaly_score=0.9)
        }
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        await engine.trigger_response(ip, "s1", 0.92)
        assert sessions["s1"].status is SessionStatus.REVOKED

    @pytest.mark.asyncio
    async def test_revocation_delta_non_negative(
        self, fresh_hub, blank_blacklist, tmp_db
    ) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine

        ip = "203.0.113.21"
        sessions = {
            "s1": SessionRecord(session_id="s1", ip_address=ip, role="Guest", anomaly_score=0.9)
        }
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        await engine.trigger_response(ip, "s1", 0.9)
        delta = sessions["s1"].revocation_delta_ms
        assert delta is not None
        assert delta >= 0.0

    @pytest.mark.asyncio
    async def test_already_revoked_session_not_re_revoked(
        self, fresh_hub, blank_blacklist
    ) -> None:
        from src.soc_pipeline.soar_engine import SOAREngine
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator

        ip = "203.0.113.22"
        revoked_at_original = time.time() * 1000 - 5000
        sessions = {
            "s1": SessionRecord(
                session_id="s1",
                ip_address=ip,
                role="Guest",
                anomaly_score=0.9,
                status=SessionStatus.REVOKED,
                revoked_at_ms=revoked_at_original,
            )
        }
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        # Revoke again — should not overwrite revoked_at_ms
        result = engine._revoke_sessions_for_ip(ip)
        assert len(result) == 0  # already REVOKED, so 0 newly revoked
        assert sessions["s1"].revoked_at_ms == revoked_at_original

    @pytest.mark.asyncio
    async def test_sqldb_sessions_revoked_for_ip(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "10.0.0.30"
        t1 = auth_db.create_session("soc_engineer", "engineer", ip)
        t2 = auth_db.create_session("employee_test", "user", ip)
        count = auth_db.revoke_sessions_for_ip(ip)
        assert count == 2
        assert auth_db.get_session(t1) is None
        assert auth_db.get_session(t2) is None

    @pytest.mark.asyncio
    async def test_active_sessions_excludes_revoked(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "10.0.0.31"
        token = auth_db.create_session("soc_engineer", "engineer", ip)
        auth_db.revoke_sessions_for_ip(ip)
        active = auth_db.get_active_sessions()
        tokens = {s["token"] for s in active}
        assert token not in tokens

    @pytest.mark.asyncio
    async def test_session_status_field_in_memory(self, fresh_hub, blank_blacklist) -> None:
        from src.soc_pipeline.soar_engine import SOAREngine
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator

        ip = "203.0.113.23"
        sessions = {
            "s1": SessionRecord(session_id="s1", ip_address=ip, role="Guest", anomaly_score=0.9),
            "s2": SessionRecord(session_id="s2", ip_address="10.0.0.99", role="Admin", anomaly_score=0.1),
        }
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        revoked = engine._revoke_sessions_for_ip(ip)
        assert "s1" in revoked
        assert "s2" not in revoked
        assert sessions["s2"].status is SessionStatus.ACTIVE
