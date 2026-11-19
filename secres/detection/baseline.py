"""Niveau 3 - profils de comportement normal par agent (méthodes statistiques explicables).

Pour chaque agent vérifié, on apprend : les ressources et outils habituels, la distribution des
quantités par ressource (moyenne/écart-type de Welford) et le débit d'événements (fenêtre glissante).
Une fois ``min_events`` observations propres collectées, le profil est « établi » et chaque
nouvel événement est comparé : ressource/outil jamais vus, quantité à plus de ``z_threshold``
écarts-types, débit à plus de ``z_threshold`` écarts-types. Les événements anormaux ne sont pas appris,
ce qui limite l'empoisonnement du profil.
"""
import math
from collections import Counter, deque

from .findings import Finding


class Welford:
    def __init__(self):
        self.n, self.mean, self._m2 = 0, 0.0, 0.0

    def add(self, x):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self._m2 += delta * (x - self.mean)

    @property
    def std(self):
        return math.sqrt(self._m2 / (self.n - 1)) if self.n > 1 else 0.0

    def to_dict(self):
        return {"n": self.n, "mean": round(self.mean, 3), "std": round(self.std, 3)}


class AgentProfile:
    def __init__(self, rate_window):
        self.events = 0
        self.resources = Counter()
        self.tools = Counter()
        self.event_types = Counter()
        self.quantity = {}  # clé de ressource -> Welford
        self.rate = Welford()
        self.recent = deque(maxlen=2000)
        self.rate_window = rate_window

    def current_rate(self, now):
        while self.recent and now - self.recent[0] > self.rate_window:
            self.recent.popleft()
        return len(self.recent)

    def learn(self, ev, rate):
        self.events += 1
        self.resources[ev.resource_key] += 1
        self.event_types[ev.event_type] += 1
        if ev.tool_name:
            self.tools[ev.tool_name] += 1
        self.quantity.setdefault(ev.resource_key, Welford()).add(ev.quantity)
        self.rate.add(rate)

    def to_dict(self, min_events):
        return {
            "events_observed": self.events,
            "established": self.events >= min_events,
            "event_types": dict(self.event_types),
            "resources": dict(self.resources),
            "tools": dict(self.tools),
            "quantity_by_resource": {k: v.to_dict() for k, v in self.quantity.items()},
            "event_rate": self.rate.to_dict(),
        }


class BaselineProfiler:
    def __init__(self, config):
        self.cfg = config["baseline"]
        self.recommended = config["recommended_actions"]
        self._profiles = {}

    def profile(self, agent_id):
        profile = self._profiles.get(agent_id)
        return profile.to_dict(self.cfg["min_events"]) if profile else None

    def evaluate(self, ev, learn_allowed=True):
        """Compare l'événement au profil ; renvoie [(Finding, dedup_key)] et apprend si l'événement est normal."""
        if not self.cfg["enabled"] or not ev.identity_verified:
            return []
        profile = self._profiles.setdefault(ev.agent_id, AgentProfile(self.cfg["rate_window_seconds"]))
        profile.recent.append(ev.received_at)
        rate = profile.current_rate(ev.received_at)
        deviations = []
        if profile.events >= self.cfg["min_events"]:
            deviations = self._deviations(profile, ev, rate)
        if not deviations:
            if learn_allowed:
                profile.learn(ev, rate)
            return []
        return [self._build(ev, profile, deviations)]  # liste d'un tuple (Finding, clé)

    def _deviations(self, profile, ev, rate):
        cfg = self.cfg
        found = []
        if ev.resource_key not in profile.resources:
            found.append({"kind": "new_resource", "severity": cfg["severity_new_resource"],
                          "resource": ev.resource_key, "known_resources": sorted(profile.resources)})
        if ev.tool_name and ev.tool_name not in profile.tools:
            found.append({"kind": "new_tool", "severity": cfg["severity_new_tool"],
                          "tool": ev.tool_name, "known_tools": sorted(profile.tools)})
        stats = profile.quantity.get(ev.resource_key)
        if stats and stats.n >= cfg["min_quantity_samples"]:
            z = (ev.quantity - stats.mean) / max(stats.std, cfg["min_std"])
            if z >= cfg["z_threshold"]:
                found.append({"kind": "quantity_outlier", "severity": cfg["severity_quantity"],
                              "resource": ev.resource_key, "quantity": ev.quantity,
                              "baseline_mean": round(stats.mean, 2), "baseline_std": round(stats.std, 2),
                              "z_score": round(z, 2), "z_threshold": cfg["z_threshold"]})
        if profile.rate.n >= cfg["min_quantity_samples"] and rate >= cfg["min_rate_count"]:
            z = (rate - profile.rate.mean) / max(profile.rate.std, cfg["min_std"])
            if z >= cfg["z_threshold"]:
                found.append({"kind": "rate_spike", "severity": cfg["severity_rate"],
                              "events_in_window": rate, "window_seconds": cfg["rate_window_seconds"],
                              "baseline_mean": round(profile.rate.mean, 2),
                              "baseline_std": round(profile.rate.std, 2), "z_score": round(z, 2)})
        return found

    def _build(self, ev, profile, deviations):
        order = ["low", "medium", "high", "critical"]
        severity = max((d["severity"] for d in deviations), key=order.index)
        kinds = [d["kind"] for d in deviations]
        finding = Finding(
            agent_id=ev.agent_id, session_id=ev.session_id, trace_id=ev.trace_id,
            detection_type="baseline_deviation", severity=severity,
            description="Écart par rapport au comportement habituel de l'agent : " + ", ".join(kinds) + ".",
            evidence={"deviations": deviations, "baseline_events": profile.events, "resource": ev.resource_key},
            level=3, event_id=ev.event_id,
            recommended_action=self.recommended.get("baseline_deviation", self.recommended["default"]),
        )
        return finding, ("baseline_deviation", ev.agent_id, ev.resource_key, tuple(sorted(kinds)))
