"""Niveau 2 - détection comportementale sur fenêtres de temps configurables."""
from collections import defaultdict, deque

from .findings import Finding


def _matches(step, ev):
    """Un pas de séquence correspond si tous ses champs renseignés égalent ceux de l'événement."""
    fields = {"event_type": ev.event_type, "resource_type": ev.resource_type,
              "resource_id": ev.resource_id, "action": ev.action, "tool_name": ev.tool_name}
    return all(value in ("*", fields.get(key)) for key, value in step.items())


class WindowDetector:
    def __init__(self, config):
        self.cfg = config["time_window"]
        self.recommended = config["recommended_actions"]
        self._history = defaultdict(deque)  # acteur -> deque[StandardEvent]

    def _finding(self, ev, detection_type, severity, description, evidence, dedup_key):
        finding = Finding(
            agent_id=ev.agent_id, session_id=ev.session_id, trace_id=ev.trace_id,
            detection_type=detection_type, severity=severity, description=description,
            evidence=evidence, level=2, event_id=ev.event_id,
            recommended_action=self.recommended.get(detection_type, self.recommended["default"]),
        )
        return finding, dedup_key

    def _in_window(self, events, now, seconds):
        return [e for e in events if now - e.received_at <= seconds]

    def evaluate(self, ev):
        """Enregistre l'événement puis renvoie une liste de (Finding, clé_de_déduplication)."""
        history = self._history[ev.actor_key]
        history.append(ev)
        while history and ev.received_at - history[0].received_at > self.cfg["history_seconds"]:
            history.popleft()
        now = ev.received_at
        events = list(history)
        results = []
        for check in (self._excessive_reads, self._customer_volume, self._payment_calls,
                      self._tool_frequency, self._gradual_exfiltration, self._sequences):
            results.extend(check(ev, events, now))
        return results

    def _excessive_reads(self, ev, events, now):
        cfg = self.cfg["excessive_reads"]
        if ev.event_type != "acces_donnees":
            return []
        reads = [e for e in self._in_window(events, now, cfg["window_seconds"]) if e.event_type == "acces_donnees"]
        if len(reads) < cfg["max_reads"]:
            return []
        return [self._finding(
            ev, "excessive_data_reads", cfg["severity"],
            f"{len(reads)} lectures de données en {cfg['window_seconds']} s (seuil {cfg['max_reads']}).",
            {"reads": len(reads), "window_seconds": cfg["window_seconds"], "threshold": cfg["max_reads"],
             "event_ids": [e.event_id for e in reads[-10:]]},
            ("excessive_data_reads",))]

    def _customer_volume(self, ev, events, now):
        cfg = self.cfg["customer_record_volume"]
        if ev.event_type != "acces_donnees" or ev.resource_key != cfg["resource"]:
            return []
        reads = [e for e in self._in_window(events, now, cfg["window_seconds"])
                 if e.event_type == "acces_donnees" and e.resource_key == cfg["resource"]]
        total = sum(e.quantity for e in reads)
        if len(reads) < cfg["min_requests"] or total < cfg["max_records"]:
            return []
        return [self._finding(
            ev, "customer_record_volume", cfg["severity"],
            f"{total} fiches clients lues en {cfg['window_seconds']} s (seuil {cfg['max_records']}).",
            {"records": total, "requests": len(reads), "window_seconds": cfg["window_seconds"],
             "threshold": cfg["max_records"], "resource": cfg["resource"]},
            ("customer_record_volume",))]

    def _payment_calls(self, ev, events, now):
        cfg = self.cfg["payment_api_calls"]
        if ev.event_type != "appel_outil" or ev.tool_name != cfg["tool"]:
            return []
        calls = [e for e in self._in_window(events, now, cfg["window_seconds"])
                 if e.event_type == "appel_outil" and e.tool_name == cfg["tool"]]
        total = sum(max(1, e.quantity) for e in calls)
        if total < cfg["max_calls"]:
            return []
        return [self._finding(
            ev, "repeated_payment_api_calls", cfg["severity"],
            f"{total} appels à '{cfg['tool']}' en {cfg['window_seconds']} s (seuil {cfg['max_calls']}).",
            {"calls": total, "requests": len(calls), "window_seconds": cfg["window_seconds"],
             "threshold": cfg["max_calls"], "tool": cfg["tool"]},
            ("repeated_payment_api_calls", cfg["tool"]))]

    def _tool_frequency(self, ev, events, now):
        cfg = self.cfg["tool_frequency"]
        if ev.event_type != "appel_outil" or not ev.tool_name:
            return []
        calls = [e for e in self._in_window(events, now, cfg["window_seconds"])
                 if e.event_type == "appel_outil" and e.tool_name == ev.tool_name]
        total = sum(max(1, e.quantity) for e in calls)
        if total < cfg["max_calls_per_tool"]:
            return []
        return [self._finding(
            ev, "abnormal_tool_frequency", cfg["severity"],
            f"Fréquence anormale de l'outil '{ev.tool_name}' : {total} appels en {cfg['window_seconds']} s.",
            {"tool": ev.tool_name, "calls": total, "window_seconds": cfg["window_seconds"],
             "threshold": cfg["max_calls_per_tool"]},
            ("abnormal_tool_frequency", ev.tool_name))]

    def _gradual_exfiltration(self, ev, events, now):
        """Beaucoup de petites lectures, chacune sous le seuil unitaire, mais volumineuses cumulées."""
        cfg = self.cfg["gradual_exfiltration"]
        if ev.event_type != "acces_donnees" or ev.resource_key != cfg["resource"]:
            return []
        small = [e for e in self._in_window(events, now, cfg["window_seconds"])
                 if e.event_type == "acces_donnees" and e.resource_key == cfg["resource"]
                 and 0 < e.quantity <= cfg["max_records_per_request"]]
        total = sum(e.quantity for e in small)
        if len(small) < cfg["min_requests"] or total < cfg["cumulative_records"]:
            return []
        return [self._finding(
            ev, "gradual_exfiltration", cfg["severity"],
            f"{len(small)} petites lectures (<= {cfg['max_records_per_request']} fiches) totalisent "
            f"{total} fiches en {cfg['window_seconds']} s : exfiltration progressive probable.",
            {"requests": len(small), "cumulative_records": total, "window_seconds": cfg["window_seconds"],
             "max_records_per_request": cfg["max_records_per_request"],
             "cumulative_threshold": cfg["cumulative_records"], "resource": cfg["resource"],
             "event_ids": [e.event_id for e in small[-10:]]},
            ("gradual_exfiltration", cfg["resource"]))]

    def _sequences(self, ev, events, now):
        results = []
        for seq in self.cfg.get("sequences", []):
            steps = seq["steps"]
            if not _matches(steps[-1], ev):
                continue
            earlier = [e for e in self._in_window(events, now, seq["window_seconds"]) if e is not ev]
            matched, position = [], 0
            for candidate in earlier:  # recherche en ordre (sous-séquence) des pas précédents
                if position < len(steps) - 1 and _matches(steps[position], candidate):
                    matched.append(candidate)
                    position += 1
            if position == len(steps) - 1:
                results.append(self._finding(
                    ev, "suspicious_sequence", seq["severity"],
                    f"Séquence suspecte '{seq['name']}' détectée en {seq['window_seconds']} s.",
                    {"sequence": seq["name"], "window_seconds": seq["window_seconds"],
                     "event_ids": [e.event_id for e in matched] + [ev.event_id]},
                    ("suspicious_sequence", seq["name"])))
        return results
