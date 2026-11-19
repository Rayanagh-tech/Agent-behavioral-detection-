import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from secres.app import SecResApp  # noqa: E402
from secres.config import load_access_control, load_detection_config  # noqa: E402
from secres.detection import BehavioralDetectionEngine  # noqa: E402
from secres.events import StandardEvent  # noqa: E402
from secres.telemetry import Telemetry  # noqa: E402
from server import make_server  # noqa: E402


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def _run_from_project_root(monkeypatch):
    monkeypatch.chdir(ROOT)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def det_config():
    return load_detection_config()


@pytest.fixture
def acl():
    return load_access_control()


@pytest.fixture
def engine(det_config, acl):
    return BehavioralDetectionEngine(det_config, acl)


@pytest.fixture
def make_event(clock):
    counter = {"n": 0}

    def _make(agent_id="agent-a", role="assistance", session="s-1", etype="acces_donnees", action="lecture",
              rtype="jeu_donnees", rid="clients", qty=1, bytes_=0, tool="", approval=(None, None),
              verified=True, flags=None, trace="t" * 32, at=None, source_ip="10.0.0.1"):
        counter["n"] += 1
        return StandardEvent(
            event_id=f"e{counter['n']}", parent_event_id="", timestamp="2026-01-01T00:00:00.000Z",
            received_at=clock() if at is None else at, agent_id=agent_id, agent_role=role,
            session_id=session, trace_id=trace, span_id="s" * 16, event_type=etype, action=action,
            resource_type=rtype, resource_id=rid, tool_name=tool or (rid if rtype == "outil" else ""),
            quantity=qty, bytes_transferred=bytes_, approval_required=approval[0], approval_granted=approval[1],
            scenario="test", source_ip=source_ip, identity_verified=verified, identity_flags=list(flags or []))

    return _make


@pytest.fixture
def app(tmp_path, clock):
    telemetry = Telemetry("secres-server-test", known_tools=["api_paiement"])
    return SecResApp(log_dir=tmp_path, signing_key="cle-de-test", telemetry=telemetry, clock=clock)


@pytest.fixture
def http_server(app):
    server = make_server(app, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", app
    server.shutdown()
    server.server_close()


def secret_of(agent_id):
    return f"demo-secret-{agent_id}"
