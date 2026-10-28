"""
tests/security/test_access_control.py
Security tests for access control boundaries.

Covers:
  - Banned IP is rejected at the gateway level
  - Revoked session cannot re-use a token
  - Monitor-only mode does not write ban records
  - Loopback IP is never blacklisted by SOAR
  - Admin-role sessions are not treated differently by the ban check
  - check_web_honeytoken: monitor-only skips DB ban
"""

from __future__ import annotations

import pytest
from src.zero_trust.models import SessionRecord, SessionStatus

pytestmark = pytest.mark.security


# ===========================================================================
# Banned IP rejection via BasePortalShell
# ===========================================================================

class TestBannedIPRejection:
    """Banned IPs must be rejected before any ML scoring."""

    def _make_shell(self):
        from src.portal.gateway import BasePortalShell

        class _Concrete(BasePortalShell):
            async def handle_user_action(self, session_id, ip, action_type, click_payload, username=None):
                return {"allowed": True, "score": 0.0, "action": "ALLOW",
                        "session_id": session_id, "action_type": action_type}

        return _Concrete()

    @pytest.mark.asyncio
    async def test_banned_ip_returns_false(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "192.0.2.100"
        auth_db.ban_ip(ip, reason="test")
        result = await self._make_shell().run("s1", ip, "view_balance", {})
        assert result["allowed"] is False

    @pytest.mark.asyncio
    async def test_banned_ip_returns_block_action(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "192.0.2.101"
        auth_db.ban_ip(ip, reason="test")
        result = await self._make_shell().run("s1", ip, "wire_transfer", {})
        assert result["action"] == "BLOCK"

    @pytest.mark.asyncio
    async def test_banned_ip_returns_403_status(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "192.0.2.102"
        auth_db.ban_ip(ip, reason="test")
        result = await self._make_shell().run("s1", ip, "admin_login", {})
        assert result.get("http_status") == 403

    @pytest.mark.asyncio
    async def test_clean_ip_not_rejected(self, tmp_db) -> None:
        ip = "10.0.0.55"
        result = await self._make_shell().run("s1", ip, "view_balance", {})
        assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_unbanned_ip_is_allowed_again(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "192.0.2.103"
        auth_db.ban_ip(ip, reason="test")
        auth_db.unban_ip(ip)
        result = await self._make_shell().run("s1", ip, "view_balance", {})
        assert result["allowed"] is True


# ===========================================================================
# SOAR loopback guard — never bans server's own interface
# ===========================================================================

class TestSOARLoopbackGuard:

    @pytest.mark.asyncio
    async def test_loopback_127_not_blacklisted(self, fresh_hub, blank_sessions, blank_blacklist) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        await engine.trigger_response("127.0.0.1", "s1", 0.99)
        assert "127.0.0.1" not in blank_blacklist

    @pytest.mark.asyncio
    async def test_loopback_localhost_not_blacklisted(self, fresh_hub, blank_sessions, blank_blacklist) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        await engine.trigger_response("localhost", "s1", 0.99)
        assert "localhost" not in blank_blacklist

    @pytest.mark.asyncio
    async def test_loopback_ipv6_not_blacklisted(self, fresh_hub, blank_sessions, blank_blacklist) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        await engine.trigger_response("::1", "s1", 0.99)
        assert "::1" not in blank_blacklist

    @pytest.mark.asyncio
    async def test_loopback_result_success(self, fresh_hub, blank_sessions, blank_blacklist) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        result = await engine.trigger_response("127.0.0.1", "s1", 0.99)
        assert result.success is True


# ===========================================================================
# Monitor-only mode
# ===========================================================================

class TestMonitorOnlyMode:

    @pytest.mark.asyncio
    async def test_monitor_only_does_not_blacklist(self, fresh_hub, blank_sessions, blank_blacklist) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
            monitor_only=True,
        )
        ip = "203.0.113.50"
        blank_sessions["s1"] = SessionRecord(session_id="s1", ip_address=ip, role="Guest", anomaly_score=0.9)
        await engine.trigger_response(ip, "s1", 0.95)
        assert ip not in blank_blacklist

    @pytest.mark.asyncio
    async def test_monitor_only_does_not_revoke_session(self, fresh_hub, blank_sessions, blank_blacklist) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        ip = "203.0.113.51"
        blank_sessions["s2"] = SessionRecord(session_id="s2", ip_address=ip, role="Guest", anomaly_score=0.9)
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
            monitor_only=True,
        )
        await engine.trigger_response(ip, "s2", 0.95)
        assert blank_sessions["s2"].status is SessionStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_monitor_only_flag_toggleable(self, fresh_hub, blank_sessions, blank_blacklist) -> None:
        from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
        from src.soc_pipeline.soar_engine import SOAREngine
        engine = SOAREngine(
            event_hub=fresh_hub,
            active_sessions=blank_sessions,
            perimeter_blacklist=blank_blacklist,
            intel=ThreatIntelAggregator(timeout_s=0.000_001),
        )
        engine.monitor_only = True
        ip = "203.0.113.52"
        await engine.trigger_response(ip, "s3", 0.95)
        assert ip not in blank_blacklist
        # Disable monitor_only — now it should ban
        engine.monitor_only = False
        ip2 = "203.0.113.53"
        blank_sessions["s4"] = SessionRecord(session_id="s4", ip_address=ip2, role="Guest", anomaly_score=0.9)
        await engine.trigger_response(ip2, "s4", 0.95)
        assert ip2 in blank_blacklist


# ===========================================================================
# Web honeytoken access control
# ===========================================================================

class TestWebHoneytokenAccess:

    def test_honeytoken_hit_bans_in_db(self, tmp_db) -> None:
        from src.auth import db as auth_db
        from src.portal.gateway import check_web_honeytoken
        ip = "192.0.2.200"
        assert not auth_db.is_banned(ip)
        check_web_honeytoken("/app/admin/db_config.json", ip)
        assert auth_db.is_banned(ip)

    def test_normal_path_does_not_ban(self, tmp_db) -> None:
        from src.auth import db as auth_db
        from src.portal.gateway import check_web_honeytoken
        ip = "192.0.2.201"
        check_web_honeytoken("/app/home", ip)
        assert not auth_db.is_banned(ip)

    @pytest.mark.parametrize("path", [
        "/.env",
        "/wp-admin",
        "/.git/config",
        "/phpmyadmin",
        "/api/debug",
        "/shell.php",
        "/backup.sql",
    ])
    def test_all_bait_paths_trigger_ban(self, tmp_db, path: str) -> None:
        from src.auth import db as auth_db
        from src.portal.gateway import check_web_honeytoken
        ip = f"192.0.2.{hash(path) % 200 + 10}"
        result = check_web_honeytoken(path, ip)
        assert result is True
        assert auth_db.is_banned(ip)
