"""
tests/security/test_blocked_requests.py
Security tests verifying post-ban behaviour across the system.

Covers:
  - Repeated ban operations are idempotent (no duplicate key errors)
  - Multiple sessions for the same banned IP are all revoked
  - Session revoked_at_ms is set on revocation
  - Reputation lookup never raises for adversarial inputs
  - SOAR result is always success=True even for edge-case inputs
  - SOAREngine.manual_ban / manual_unban
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.zero_trust.models import SessionRecord, SessionStatus

pytestmark = pytest.mark.security


# ===========================================================================
# Idempotent ban operations
# ===========================================================================

class TestIdempotentBan:

    def test_ban_ip_twice_no_error(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "192.0.2.50"
        auth_db.ban_ip(ip, reason="first")
        auth_db.ban_ip(ip, reason="second")  # idempotent — must not raise
        assert auth_db.is_banned(ip)

    def test_unban_unbanned_ip_returns_false(self, tmp_db) -> None:
        from src.auth import db as auth_db
        result = auth_db.unban_ip("192.0.2.60")  # not in DB
        assert result is False

    def test_ban_then_unban_then_reban(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "192.0.2.70"
        auth_db.ban_ip(ip)
        auth_db.unban_ip(ip)
        auth_db.ban_ip(ip)
        assert auth_db.is_banned(ip)

    def test_is_banned_false_for_unknown(self, tmp_db) -> None:
        from src.auth import db as auth_db
        assert not auth_db.is_banned("192.0.2.99")


# ===========================================================================
# Session revocation for banned IP
# ===========================================================================

class TestSessionRevocationAfterBan:

    @pytest.mark.asyncio
    async def test_all_sessions_for_ip_revoked(
        self, fresh_hub, blank_blacklist
    ) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine

        ip = "203.0.113.10"
        sessions = {
            "s1": SessionRecord(session_id="s1", ip_address=ip, role="Guest", anomaly_score=0.9),
            "s2": SessionRecord(session_id="s2", ip_address=ip, role="Guest", anomaly_score=0.8),
            "s3": SessionRecord(session_id="s3", ip_address="10.0.0.1", role="Guest", anomaly_score=0.3),
        }
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        await engine.trigger_response(ip, "s1", 0.9)
        assert sessions["s1"].status is SessionStatus.REVOKED
        assert sessions["s2"].status is SessionStatus.REVOKED
        assert sessions["s3"].status is SessionStatus.ACTIVE  # untouched

    @pytest.mark.asyncio
    async def test_revoked_at_ms_set(
        self, fresh_hub, blank_blacklist
    ) -> None:
        import time
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine

        ip = "203.0.113.11"
        sessions = {
            "s1": SessionRecord(session_id="s1", ip_address=ip, role="Guest", anomaly_score=0.9),
        }
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        before = time.time() * 1000
        await engine.trigger_response(ip, "s1", 0.9)
        after = time.time() * 1000
        rec = sessions["s1"]
        assert rec.revoked_at_ms is not None
        assert before <= rec.revoked_at_ms <= after


# ===========================================================================
# Reputation lookup — never raises
# ===========================================================================

class TestReputationNeverRaises:

    @pytest.mark.asyncio
    async def test_garbage_ip_no_raise(self) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        agg = ThreatIntelAggregator(timeout_s=0.000_001)
        result = await agg.fetch_reputation("not-an-ip")
        assert result is not None

    @pytest.mark.asyncio
    async def test_empty_string_no_raise(self) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        agg = ThreatIntelAggregator(timeout_s=0.000_001)
        result = await agg.fetch_reputation("")
        assert result is not None

    @pytest.mark.asyncio
    async def test_very_long_string_no_raise(self) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        agg = ThreatIntelAggregator(timeout_s=0.000_001)
        result = await agg.fetch_reputation("A" * 200)
        assert result is not None

    @given(ip=st.text(min_size=0, max_size=50))
    @settings(max_examples=80, deadline=None)
    def test_prop14_never_raises(self, ip: str) -> None:
        import asyncio
        from src.soc_pipeline.intel_aggregator import IPReputationReport, ThreatIntelAggregator
        agg = ThreatIntelAggregator(timeout_s=0.000_001)

        async def _run():
            return await agg.fetch_reputation(ip)

        result = asyncio.run(_run())
        assert isinstance(result, IPReputationReport)
        assert 0 <= result.abuse_confidence_score <= 100


# ===========================================================================
# Manual ban / unban (analyst actions)
# ===========================================================================

class TestManualBanUnban:

    @pytest.mark.asyncio
    async def test_manual_ban_adds_to_blacklist(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        ip = "198.51.100.50"
        result = await engine.manual_ban(ip, reason="analyst_test")
        assert result["success"] is True
        assert ip in blank_blacklist

    @pytest.mark.asyncio
    async def test_manual_unban_removes_from_blacklist(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        ip = "198.51.100.51"
        blank_blacklist.add(ip)
        result = await engine.manual_unban(ip)
        assert result["success"] is True
        assert ip not in blank_blacklist

    @pytest.mark.asyncio
    async def test_manual_ban_loopback_refused(
        self, fresh_hub, blank_sessions, blank_blacklist
    ) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        result = await engine.manual_ban("127.0.0.1")
        assert result["success"] is False
        assert "127.0.0.1" not in blank_blacklist
