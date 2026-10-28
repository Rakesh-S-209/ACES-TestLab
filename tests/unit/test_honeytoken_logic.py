"""
tests/unit/test_honeytoken_logic.py
Unit tests for src/deception/token_watcher.py

Covers:
  - Property 15: file event on db_config.json → exactly one HONEYTOKEN_ACCESS alert
  - Property 16: directory events always ignored
  - Property 17: alert enqueued via call_soon_threadsafe (thread-safe bridging)
  - Non-target file events ignored
  - Alert field correctness (type, source_ip, affected_path, timestamp)
  - HoneytokenWatcher construction creates honeytoken file
  - Watcher lifecycle: start() + stop()
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler(hub, loop):
    from src.deception.token_watcher import _HoneytokenEventHandler
    return _HoneytokenEventHandler(event_hub=hub, loop=loop)


def _file_event(path: str, is_dir: bool = False):
    evt = MagicMock()
    evt.is_directory = is_dir
    evt.src_path = path
    return evt


# ===========================================================================
# _HoneytokenEventHandler
# ===========================================================================

class TestHoneytokenEventHandler:

    # ── Property 16: directory events ignored ────────────────────────────────

    def test_directory_event_no_alert(self, fresh_hub, tmp_path) -> None:
        loop = asyncio.new_event_loop()
        calls: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda *a: calls.append(a))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        handler.on_any_event(_file_event(str(tmp_path), is_dir=True))
        assert len(calls) == 0
        loop.close()

    @given(
        dirname=st.text(
            min_size=1, max_size=20,
            alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_-"),
        )
    )
    @settings(max_examples=50)
    def test_prop16_directory_always_ignored(self, dirname: str, fresh_hub) -> None:
        loop = asyncio.new_event_loop()
        calls: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda *a: calls.append(a))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        handler.on_any_event(_file_event(f"/some/path/{dirname}", is_dir=True))
        assert len(calls) == 0
        loop.close()

    # ── Property 15: honeytoken file → exactly one alert ─────────────────────

    def test_honeytoken_file_produces_one_alert(self, fresh_hub, tmp_path) -> None:
        loop = asyncio.new_event_loop()
        enqueued: list = []

        def capture(fn, *args):
            enqueued.append(args[0] if args else fn)

        loop.call_soon_threadsafe = MagicMock(side_effect=capture)  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        handler.on_any_event(_file_event(str(tmp_path / "honey_tokens" / "db_config.json")))
        assert len(enqueued) == 1
        loop.close()

    def test_alert_type_is_honeytoken_access(self, fresh_hub, tmp_path) -> None:
        from src.zero_trust.models import AlertType
        loop = asyncio.new_event_loop()
        enqueued: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda fn, alert: enqueued.append(alert))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        handler.on_any_event(_file_event(str(tmp_path / "db_config.json")))
        assert enqueued[0].alert_type is AlertType.HONEYTOKEN_ACCESS
        loop.close()

    def test_source_ip_is_local(self, fresh_hub, tmp_path) -> None:
        loop = asyncio.new_event_loop()
        enqueued: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda fn, alert: enqueued.append(alert))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        handler.on_any_event(_file_event(str(tmp_path / "db_config.json")))
        assert enqueued[0].source_ip == "local"
        loop.close()

    def test_affected_path_is_absolute(self, fresh_hub, tmp_path) -> None:
        loop = asyncio.new_event_loop()
        enqueued: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda fn, alert: enqueued.append(alert))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        handler.on_any_event(_file_event(str(tmp_path / "honey_tokens" / "db_config.json")))
        assert os.path.isabs(enqueued[0].affected_path)
        loop.close()

    def test_timestamp_within_wall_clock(self, fresh_hub, tmp_path) -> None:
        loop = asyncio.new_event_loop()
        enqueued: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda fn, alert: enqueued.append(alert))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        before = time.time() * 1000
        handler.on_any_event(_file_event(str(tmp_path / "db_config.json")))
        after = time.time() * 1000
        ts = enqueued[0].timestamp_ms
        assert before <= ts <= after
        loop.close()

    # ── Non-target file ignored ──────────────────────────────────────────────

    def test_non_target_file_ignored(self, fresh_hub, tmp_path) -> None:
        loop = asyncio.new_event_loop()
        enqueued: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda fn, alert: enqueued.append(alert))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        for bad in ["other_file.txt", "db_config.json.bak", "readme.md", "config.yml"]:
            handler.on_any_event(_file_event(str(tmp_path / bad)))
        assert len(enqueued) == 0
        loop.close()

    def test_db_config_bak_not_target(self, fresh_hub, tmp_path) -> None:
        """Partial name match must not trigger alert."""
        loop = asyncio.new_event_loop()
        enqueued: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda fn, alert: enqueued.append(alert))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        handler.on_any_event(_file_event(str(tmp_path / "db_config.json.bak")))
        assert len(enqueued) == 0
        loop.close()

    # ── Property 17: must use call_soon_threadsafe ────────────────────────────

    def test_prop17_uses_call_soon_threadsafe(self, fresh_hub, tmp_path) -> None:
        loop = asyncio.new_event_loop()
        calls: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda *a: calls.append(a))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        handler.on_any_event(_file_event(str(tmp_path / "honey_tokens" / "db_config.json")))
        loop.call_soon_threadsafe.assert_called_once()  # type: ignore[union-attr]
        loop.close()

    # ── Multiple events — one alert each ────────────────────────────────────

    def test_two_file_events_produce_two_alerts(self, fresh_hub, tmp_path) -> None:
        loop = asyncio.new_event_loop()
        enqueued: list = []
        loop.call_soon_threadsafe = MagicMock(side_effect=lambda fn, alert: enqueued.append(alert))  # type: ignore[method-assign]
        handler = _make_handler(fresh_hub, loop)
        path = str(tmp_path / "db_config.json")
        handler.on_any_event(_file_event(path))
        handler.on_any_event(_file_event(path))
        assert len(enqueued) == 2
        loop.close()


# ===========================================================================
# HoneytokenWatcher construction and lifecycle
# ===========================================================================

class TestHoneytokenWatcherLifecycle:

    def test_constructor_creates_watch_dir(self, fresh_hub, tmp_path) -> None:
        from src.deception.token_watcher import HoneytokenWatcher
        watch_dir = tmp_path / "honey_tokens"
        loop = asyncio.new_event_loop()
        HoneytokenWatcher(watch_path=watch_dir, event_hub=fresh_hub, loop=loop)
        assert watch_dir.exists()
        loop.close()

    def test_constructor_creates_honeytoken_file(self, fresh_hub, tmp_path) -> None:
        from src.deception.token_watcher import HoneytokenWatcher
        watch_dir = tmp_path / "honey_tokens"
        loop = asyncio.new_event_loop()
        HoneytokenWatcher(watch_path=watch_dir, event_hub=fresh_hub, loop=loop)
        assert (watch_dir / "db_config.json").exists()
        loop.close()

    def test_honeytoken_file_is_valid_json(self, fresh_hub, tmp_path) -> None:
        from src.deception.token_watcher import HoneytokenWatcher
        watch_dir = tmp_path / "honey_tokens"
        loop = asyncio.new_event_loop()
        HoneytokenWatcher(watch_path=watch_dir, event_hub=fresh_hub, loop=loop)
        content = (watch_dir / "db_config.json").read_text(encoding="utf-8")
        data = json.loads(content)
        assert isinstance(data, dict)
        loop.close()

    def test_honeytoken_file_contains_password_key(self, fresh_hub, tmp_path) -> None:
        from src.deception.token_watcher import HoneytokenWatcher
        watch_dir = tmp_path / "honey_tokens"
        loop = asyncio.new_event_loop()
        HoneytokenWatcher(watch_path=watch_dir, event_hub=fresh_hub, loop=loop)
        data = json.loads((watch_dir / "db_config.json").read_text())
        assert "password" in data  # decoy credential must be present
        loop.close()

    def test_start_and_stop_lifecycle(self, fresh_hub, tmp_path) -> None:
        from src.deception.token_watcher import HoneytokenWatcher
        watch_dir = tmp_path / "honey_tokens"
        loop = asyncio.new_event_loop()
        watcher = HoneytokenWatcher(watch_path=watch_dir, event_hub=fresh_hub, loop=loop)
        watcher.start()
        assert watcher._observer is not None
        watcher.stop()
        assert watcher._observer is None
        loop.close()

    def test_stop_without_start_is_safe(self, fresh_hub, tmp_path) -> None:
        from src.deception.token_watcher import HoneytokenWatcher
        watch_dir = tmp_path / "honey_tokens"
        loop = asyncio.new_event_loop()
        watcher = HoneytokenWatcher(watch_path=watch_dir, event_hub=fresh_hub, loop=loop)
        watcher.stop()  # must not raise
        loop.close()

    def test_existing_file_not_overwritten(self, fresh_hub, tmp_path) -> None:
        from src.deception.token_watcher import HoneytokenWatcher
        watch_dir = tmp_path / "honey_tokens"
        watch_dir.mkdir(parents=True)
        token_path = watch_dir / "db_config.json"
        token_path.write_text('{"custom": "value"}', encoding="utf-8")
        loop = asyncio.new_event_loop()
        HoneytokenWatcher(watch_path=watch_dir, event_hub=fresh_hub, loop=loop)
        # Existing file should not be overwritten
        assert json.loads(token_path.read_text())["custom"] == "value"
        loop.close()
