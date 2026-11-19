"""Moteur de détection comportementale : orchestre les niveaux 1, 2 et 3.

Le moteur ne dépend PAS de la télémétrie : il consomme des ``StandardEvent`` et produit des
``Finding``. La mesure (spans, métriques) est faite par l'appelant (voir ``secres.app``).
"""
import threading

from .baseline import BaselineProfiler
from .findings import FindingStore
from .rules import Level1Rules
from .windows import WindowDetector


class BehavioralDetectionEngine:
    def __init__(self, config, access_control, store=None):
        self.config = config
        self.rules = Level1Rules(config, access_control)
        self.windows = WindowDetector(config)
        self.baselines = BaselineProfiler(config)
        self.store = store if store is not None else FindingStore()
        self._cooldown = config["cooldown_seconds"]
        self._last_emitted = {}
        self._lock = threading.Lock()

    def process(self, event):
        """Analyse un événement standardisé et renvoie la liste des findings générés."""
        with self._lock:
            level1 = self.rules.evaluate(event)
            candidates = list(self.windows.evaluate(event))
            level3 = self.baselines.evaluate(event, learn_allowed=not level1 and not candidates)
            candidates.extend(level3)
            findings = list(level1)
            for finding, key in candidates:
                if self._allowed_by_cooldown((event.actor_key,) + key, event.received_at):
                    findings.append(finding)
            for finding in findings:
                self.store.add(finding)
            return findings

    def _allowed_by_cooldown(self, key, now):
        last = self._last_emitted.get(key)
        if last is not None and now - last < self._cooldown:
            return False
        self._last_emitted[key] = now
        if len(self._last_emitted) > 10000:  # borne mémoire
            oldest = sorted(self._last_emitted, key=self._last_emitted.get)[:5000]
            for stale in oldest:
                del self._last_emitted[stale]
        return True

    def get_profile(self, agent_id):
        with self._lock:
            return self.baselines.profile(agent_id)
