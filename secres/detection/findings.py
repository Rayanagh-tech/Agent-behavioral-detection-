"""Modèle de finding structuré et stockage (mémoire bornée + JSONL optionnel)."""
import json
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class Finding:
    agent_id: str
    session_id: str
    trace_id: str
    detection_type: str
    severity: str
    description: str
    evidence: dict
    recommended_action: str
    level: int = 1
    event_id: str = ""
    legacy_code: str = ""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self):
        return asdict(self)


class FindingStore:
    def __init__(self, path=None, max_items=5000):
        self._items = deque(maxlen=max_items)
        self._lock = threading.Lock()
        self._path = Path(path) if path else None
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, finding):
        with self._lock:
            self._items.append(finding)
            if self._path:
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(finding.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n")

    def get(self, finding_id):
        with self._lock:
            return next((f for f in self._items if f.finding_id == finding_id), None)

    def query(self, agent_id=None, session_id=None, trace_id=None, severity=None,
              detection_type=None, limit=100):
        with self._lock:
            items = list(self._items)
        selected = [
            f for f in reversed(items)
            if (agent_id is None or f.agent_id == agent_id)
            and (session_id is None or f.session_id == session_id)
            and (trace_id is None or f.trace_id == trace_id)
            and (severity is None or f.severity == severity)
            and (detection_type is None or f.detection_type == detection_type)
        ]
        return selected[:max(1, min(limit, 1000))]

    def count(self):
        with self._lock:
            return len(self._items)
