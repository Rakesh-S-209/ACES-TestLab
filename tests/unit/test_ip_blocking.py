"""
tests/unit/test_ip_blocking.py
Unit tests for src/portal/gateway.py

Covers:
  - WEB_HONEYTOKEN_PATHS content
  - check_web_honeytoken() return value
  - BasePortalShell.run() public-page bypass
  - BasePortalShell.run() banned-IP rejection
  - PortTrap connection handler: zero-bytes policy, blacklist, alert publication
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.portal.gateway import WEB_HONEYTOKEN_PATHS, check_web_honeytoken

pytestmark = pytest.mark.unit


# ===========================================================================
# WEB_HONEYTOKEN_PATHS content
# ===========================================================================

class TestWebHoneytokenPaths:

    def test_db_config_json_registered(self) -> None:
        assert "/app/admin/db_config.json" in WEB_HONEYTOKEN_PATHS

    def test_env_bait_registered(self) -> None:
        assert "/.env" in WEB_HONEYTOKEN_PATHS

    def test_wp_admin_registered(self) -> None:
        assert "/wp-admin" in WEB_HONEYTOKEN_PATHS

    def test_git_config_registered(self) -> None:
        assert "/.git/config" in WEB_HONEYTOKEN_PATHS

    def test_paths_are_frozenset(self) -> None:
        assert isinstance(WEB_HONEYTOKEN_PATHS, frozenset)

    @pytest.mark.parametrize("path", [
        "/app/admin/db_config.json",
        "/app/admin/config.json",
        "/app/admin/secrets.json",
        "/.env",
        "/.env.bak",
        "/wp-admin",
        "/wp-login.php",
        "/.git/config",
        "/robots.txt",
        "/phpmyadmin",
        "/api/debug",
    ])
    def test_known_bait_paths_present(self, path: str) -> None:
        assert path in WEB_HONEYTOKEN_PATHS, f"{path!r} missing"

    def test_normal_app_path_not_in_set(self) -> None:
        for safe in ["/app/home", "/app/login", "/app/dashboard", "/api/action"]:
            assert safe not in WEB_HONEYTOKEN_PATHS, f"{safe!r} should not be a bait"


# ===========================================================================
# check_web_honeytoken()
# ===========================================================================

class TestCheckWebHoneytoken:

    def test_returns_true_for_bait_path(self, tmp_db) -> None:
        result = check_web_honeytoken("/app/admin/db_config.json", "10.0.0.1")
        assert result is True

    def test_returns_false_for_normal_path(self, tmp_db) -> None:
        result = check_web_honeytoken("/app/home", "10.0.0.1")
        assert result is False

    def test_bans_ip_in_sqlite(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "192.0.2.11"
        assert not auth_db.is_banned(ip)
        check_web_honeytoken("/app/admin/db_config.json", ip)
        assert auth_db.is_banned(ip)

    def test_monitor_only_does_not_ban(self, tmp_db) -> None:
        from src.auth import db as auth_db

        class _FakeSoar:
            monitor_only = True

        ip = "192.0.2.22"
        check_web_honeytoken("/.env", ip, soar_engine=_FakeSoar())
        assert not auth_db.is_banned(ip)

    def test_returns_false_for_safe_path(self, tmp_db) -> None:
        assert check_web_honeytoken("/api/action", "1.2.3.4") is False


# ===========================================================================
# BasePortalShell.run()
# ===========================================================================

class TestBasePortalShellRun:
    """Test the abstract base class run() method via a minimal concrete subclass."""

    def _make_shell(self):
        from src.portal.gateway import BasePortalShell

        class _ConcreteShell(BasePortalShell):
            async def handle_user_action(self, session_id, ip, action_type, click_payload, username=None):
                return {"allowed": True, "score": 0.1, "action": "ALLOW",
                        "session_id": session_id, "action_type": action_type}

        return _ConcreteShell()

    @pytest.mark.asyncio
    async def test_public_action_bypasses_ban_check(self, tmp_db) -> None:
        shell = self._make_shell()
        result = await shell.run("s1", "1.2.3.4", "public_page", {})
        assert result["allowed"] is True
        assert result.get("public") is True

    @pytest.mark.asyncio
    async def test_home_visit_is_public(self, tmp_db) -> None:
        shell = self._make_shell()
        result = await shell.run("s1", "1.2.3.4", "home_visit", {})
        assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_banned_ip_blocked(self, tmp_db) -> None:
        from src.auth import db as auth_db
        ip = "192.0.2.33"
        auth_db.ban_ip(ip, reason="test")
        shell = self._make_shell()
        result = await shell.run("s1", ip, "view_balance", {})
        assert result["allowed"] is False
        assert result.get("banned") is True

    @pytest.mark.asyncio
    async def test_clean_ip_delegates_to_handle(self, tmp_db) -> None:
        shell = self._make_shell()
        result = await shell.run("s1", "10.0.0.5", "view_balance", {})
        assert result["allowed"] is True
        assert result["action"] == "ALLOW"


# ===========================================================================
# PortTrap.handle_connection() unit tests
# ===========================================================================

class TestPortTrapHandleConnection:

    def _make_trap(self, fresh_hub):
        from src.deception.port_trap import PortTrap
        return PortTrap(event_hub=fresh_hub, perimeter_blacklist=set(), port=3389)

    def _writer(self, ip="203.0.113.5", port=54321):
        w = MagicMock(spec=asyncio.StreamWriter)
        w.get_extra_info = MagicMock(return_value=(ip, port))
        w.close = MagicMock()
        w.wait_closed = AsyncMock()
        return w

    @pytest.mark.asyncio
    async def test_zero_bytes_written(self, fresh_hub) -> None:
        trap = self._make_trap(fresh_hub)
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = self._writer()
        await trap.handle_connection(reader, writer)
        writer.write.assert_not_called()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_writelines_not_called(self, fresh_hub) -> None:
        trap = self._make_trap(fresh_hub)
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = self._writer()
        await trap.handle_connection(reader, writer)
        writer.writelines.assert_not_called()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_close_called(self, fresh_hub) -> None:
        trap = self._make_trap(fresh_hub)
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = self._writer()
        await trap.handle_connection(reader, writer)
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_ip_added_to_blacklist(self, fresh_hub) -> None:
        blacklist: set = set()
        from src.deception.port_trap import PortTrap
        trap = PortTrap(event_hub=fresh_hub, perimeter_blacklist=blacklist)
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = self._writer(ip="198.51.100.9")
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        await trap.handle_connection(reader, writer)
        assert "198.51.100.9" in blacklist

    @pytest.mark.asyncio
    async def test_one_alert_published(self, fresh_hub) -> None:
        from src.zero_trust.models import AlertType
        trap = self._make_trap(fresh_hub)
        published = []
        trap._event_hub.publish = AsyncMock(side_effect=lambda e: published.append(e))  # type: ignore[method-assign]
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = self._writer(ip="203.0.113.1")
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        await trap.handle_connection(reader, writer)
        assert len(published) == 1
        assert published[0].alert_type is AlertType.PORT_TRAP
        assert published[0].source_ip == "203.0.113.1"

    @pytest.mark.asyncio
    async def test_unknown_peername_fallback(self, fresh_hub) -> None:
        trap = self._make_trap(fresh_hub)
        published = []
        trap._event_hub.publish = AsyncMock(side_effect=lambda e: published.append(e))  # type: ignore[method-assign]
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)
        writer.get_extra_info = MagicMock(return_value=None)
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        await trap.handle_connection(reader, writer)
        assert published[0].source_ip == "unknown"

    @pytest.mark.asyncio
    async def test_alert_timestamp_within_bounds(self, fresh_hub) -> None:
        trap = self._make_trap(fresh_hub)
        published = []
        trap._event_hub.publish = AsyncMock(side_effect=lambda e: published.append(e))  # type: ignore[method-assign]
        reader = MagicMock(spec=asyncio.StreamReader)
        writer = self._writer()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        before = time.time() * 1000
        await trap.handle_connection(reader, writer)
        after = time.time() * 1000
        ts = published[0].timestamp_ms
        assert before <= ts <= after

    @pytest.mark.asyncio
    async def test_start_server_oserror_no_raise(self, fresh_hub) -> None:
        from src.deception.port_trap import PortTrap
        trap = PortTrap(event_hub=fresh_hub, perimeter_blacklist=set(), port=3389)
        with patch("asyncio.start_server", side_effect=OSError("in use")):
            await trap.start_server()  # must not raise
        assert trap._servers == {}
