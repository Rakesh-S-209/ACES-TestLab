"""
tests/conftest.py
Shared pytest fixtures for ACES-TestLab.

All fixtures are designed for complete isolation:
  - Every EventHub fixture reloads the module to reset global state.
  - Every database fixture creates a fresh file in tmp_path.
  - Scorer fixtures use synthetic fit — no behavior_model.pkl required.
  - AbuseIPDB is always called with a 1-microsecond timeout, forcing the
    offline fallback so no real network calls are made in CI.
  - TCP ports are in the 18000–19999 range to avoid privilege requirements.
"""

from __future__ import annotations

import asyncio
import importlib
from pathlib import Path
from typing import Dict, Set

import pytest

# ---------------------------------------------------------------------------
# EventHub — always reload to clear module-level globals (DEF-001 mitigation)
# ---------------------------------------------------------------------------

@pytest.fixture()
def fresh_hub():
    """
    Return a new EventHub instance backed by clean module-level globals.

    Calls importlib.reload() to reset _QUEUE, _SUBSCRIBERS, and
    _delivery_count before each test.
    """
    import src.soc_pipeline.event_hub as _hub_module
    importlib.reload(_hub_module)
    from src.soc_pipeline.event_hub import EventHub
    return EventHub()


# ---------------------------------------------------------------------------
# Shared state containers
# ---------------------------------------------------------------------------

@pytest.fixture()
def blank_blacklist() -> Set[str]:
    """Empty PERIMETER_BLACKLIST for test isolation."""
    return set()


@pytest.fixture()
def blank_sessions() -> Dict:
    """Empty ACTIVE_SESSIONS dict for test isolation."""
    return {}


# ---------------------------------------------------------------------------
# SQLite database — isolated per test via tmp_path
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    """
    Create a fresh SQLite database in tmp_path and initialise its schema.

    The real application database is NEVER touched.
    Returns the Path to the database file.
    """
    from src.auth import db as auth_db
    db_file = tmp_path / "test_aces.db"
    auth_db.init_db(db_file)
    return db_file


# ---------------------------------------------------------------------------
# TelemetryVector fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def normal_vector():
    """Benign behavioral vector — low request rate, moderate click intervals."""
    from src.zero_trust.models import TelemetryVector
    return TelemetryVector(
        click_speed_intervals=[120.0, 180.0, 150.0, 200.0],
        page_path_weights=[0.3, 0.5, 0.7],
        sequence_transitions=[1, 2, 3],
        session_duration_ms=5000.0,
        request_rate_per_sec=1.5,
    )


@pytest.fixture()
def anomalous_vector():
    """
    Highly anomalous behavioral vector — extreme rate and impossibly fast clicks.

    Designed to produce a high anomaly score when evaluated by a scorer
    trained on normal traffic.
    """
    from src.zero_trust.models import TelemetryVector
    return TelemetryVector(
        click_speed_intervals=[0.001, 0.001, 0.001],
        page_path_weights=[0.0, 1.0],
        sequence_transitions=[999999, 999998, 999997],
        session_duration_ms=50.0,
        request_rate_per_sec=9999.0,
    )


# ---------------------------------------------------------------------------
# BehaviorScorer — synthetic fit, no pkl required
# ---------------------------------------------------------------------------

@pytest.fixture()
def fitted_scorer():
    """
    Return a BehaviorScorer trained on 120 synthetic normal vectors.

    Uses random_state=42 for reproducibility.  No behavior_model.pkl needed.
    """
    from src.zero_trust.models import TelemetryVector
    from src.zero_trust.scorer import BehaviorScorer

    scorer = BehaviorScorer(n_estimators=50, contamination=0.05)
    baseline = [
        TelemetryVector(
            click_speed_intervals=[float(i % 300 + 50), float(i % 200 + 100)],
            page_path_weights=[0.4, 0.6],
            sequence_transitions=[1, 2, 3],
            session_duration_ms=float(i * 100 + 500),
            request_rate_per_sec=float(i % 10 + 1),
        )
        for i in range(120)
    ]
    scorer.fit(baseline)
    return scorer


# ---------------------------------------------------------------------------
# SOAREngine
# ---------------------------------------------------------------------------

@pytest.fixture()
def soar_engine(fresh_hub, blank_sessions, blank_blacklist):
    """
    SOAREngine wired to a fresh EventHub and empty shared state containers.

    Uses the offline-fallback ThreatIntelAggregator (1 µs timeout).
    """
    from src.soc_pipeline.intel_aggregator import ThreatIntelAggregator
    from src.soc_pipeline.soar_engine import SOAREngine

    intel = ThreatIntelAggregator(timeout_s=0.000_001)  # force offline path
    return SOAREngine(
        event_hub=fresh_hub,
        active_sessions=blank_sessions,
        perimeter_blacklist=blank_blacklist,
        intel=intel,
    )


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def make_session():
    """Factory fixture: make_session(session_id, ip, role, score) → SessionRecord."""
    from src.zero_trust.models import SessionRecord

    def _factory(
        session_id: str = "sess-001",
        ip: str = "203.0.113.5",
        role: str = "Guest",
        score: float = 0.9,
    ) -> SessionRecord:
        return SessionRecord(
            session_id=session_id,
            ip_address=ip,
            role=role,
            anomaly_score=score,
        )

    return _factory


# ---------------------------------------------------------------------------
# Ephemeral port helper
# ---------------------------------------------------------------------------

@pytest.fixture()
def ephemeral_port():
    """
    Return an available TCP port in the 18000–19999 range.

    Uses OS port 0 allocation to guarantee availability, then immediately
    releases it.  There is a small TOCTOU window but it's acceptable for
    loopback-only test servers.
    """
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
