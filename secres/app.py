"""Cœur applicatif du serveur (indépendant de HTTP) : identité -> télémétrie -> détection -> décision."""
import json
import os
import threading
import time
from pathlib import Path

from opentelemetry.trace import SpanKind

from .config import load_access_control, load_detection_config, load_json
from .detection import BehavioralDetectionEngine, FindingStore
from .events import normalize_event, now_iso
from .identity import AgentRegistry, IdentityService, SessionManager
from .telemetry import Telemetry, span_id_hex, trace_id_hex


class SecResApp:
    def __init__(self, config_dir=None, log_dir="logs", signing_key=None, telemetry=None,
                 detection_config=None, session_ttl=3600, clock=time.time, admin_token=None):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.admin_token = admin_token
        agents = load_json("agents.json", config_dir)["agents"]
        self.registry = AgentRegistry(agents)
        key = signing_key or os.urandom(32)
        self.sessions = SessionManager(self.registry, key, ttl_seconds=session_ttl, clock=clock)
        self.identity = IdentityService(self.sessions)
        self.detection_config = detection_config or load_detection_config(config_dir)
        self.store = FindingStore(self.log_dir / "findings.jsonl")
        self.engine = BehavioralDetectionEngine(self.detection_config, load_access_control(config_dir), self.store)
        self.telemetry = telemetry or Telemetry(
            "secres-server", span_dir=self.log_dir / "spans",
            known_tools=self.detection_config.get("known_tools", []))
        self._log_path = self.log_dir / "evenements.jsonl"
        self._log_lock = threading.Lock()

    # ------------------------------------------------------------------ sessions
    def open_session(self, payload, headers, source_ip):
        parent = self.telemetry.extract(headers)
        with self.telemetry.start_span("gateway.session.open", parent=parent, kind=SpanKind.SERVER) as span:
            if not isinstance(payload, dict):
                return 400, {"error": "requete_invalide"}
            agent_id = payload.get("agent_id")
            span.set_attribute("agent.id", str(agent_id)[:64])
            try:
                session, token = self.sessions.open_session(agent_id, payload.get("credential"))
            except Exception as exc:  # IdentityError et toute entrée inattendue : refus uniforme
                reason = getattr(exc, "reason", "requete_invalide")
                self.telemetry.record_identity_failure(reason)
                self.telemetry.mark_failure(span, reason)
                return 401, {"error": reason}
            span.set_attribute("session.id", session.session_id)
            span.set_attribute("agent.role", session.agent_role)
            return 200, {"session_id": session.session_id, "agent_id": session.agent_id,
                         "agent_role": session.agent_role, "token": token, "expires_at": session.expires_at}

    # ------------------------------------------------------------------ événements
    def handle_event(self, raw, headers, source_ip, source_port=0):
        headers = {k.lower(): v for k, v in headers.items()}
        parent = self.telemetry.extract(headers)
        with self.telemetry.start_span("gateway.request", parent=parent, kind=SpanKind.SERVER,
                                       attributes={"http.method": "POST", "http.route": "/event"}) as span:
            received_at = self.clock()
            trace_id, span_id = trace_id_hex(span), span_id_hex(span)
            if not isinstance(raw, dict):
                self.telemetry.mark_failure(span, "evenement_invalide")
                raise ValueError("evenement_doit_etre_un_objet")
            acteur = raw.get("acteur") if isinstance(raw.get("acteur"), dict) else {}

            with self.telemetry.start_span("identity.validate") as id_span:
                ctx, session = self.identity.resolve(
                    headers.get("x-session-token"), raw.get("agent_id"), raw.get("session_id"), acteur.get("role"))
                id_span.set_attribute("identity.verified", ctx.verified)
                id_span.set_attribute("identity.flags", ",".join(ctx.flags))
                if not ctx.verified:
                    self.telemetry.record_identity_failure(ctx.reason)
                    self.telemetry.mark_failure(id_span, ctx.reason)

            extra_flags = []
            claimed_trace = raw.get("trace_id")
            if claimed_trace and claimed_trace != trace_id and "traceparent" in headers:
                extra_flags.append("trace_mismatch")
            event = normalize_event(raw, ctx, trace_id, span_id, received_at, source_ip, extra_flags)
            if session is not None and self.sessions.note_event(session, event.event_id, trace_id):
                event.identity_flags.append("replayed_event")

            span.set_attribute("agent.id", event.agent_id)
            span.set_attribute("agent.role", event.agent_role)
            span.set_attribute("session.id", event.session_id)
            span.set_attribute("event.id", event.event_id)
            span.set_attribute("event.type", event.event_type)
            span.set_attribute("event.action", event.action)
            span.set_attribute("resource.type", event.resource_type)
            span.set_attribute("resource.id", event.resource_id)
            if event.tool_name:
                span.set_attribute("tool.name", event.tool_name)

            with self.telemetry.start_span("detection.process") as det_span:
                started = time.perf_counter()
                findings = self.engine.process(event)
                duration_ms = (time.perf_counter() - started) * 1000
                det_span.set_attribute("detection.findings", len(findings))
                det_span.set_attribute("detection.duration_ms", round(duration_ms, 3))
            self.telemetry.record_detection(duration_ms, findings)

            decision = self._decide(findings)
            event.outcome = "success" if decision == "autoriser" else ("denied" if decision == "refuser" else "flagged")
            span.set_attribute("secres.decision", decision)
            span.set_attribute("secres.outcome", event.outcome)
            span.set_attribute("secres.findings", len(findings))
            self.telemetry.add_event("secres.event", {
                "agent.id": event.agent_id, "agent.role": event.agent_role, "session.id": event.session_id,
                "trace.id": trace_id, "action": event.action, "tool.name": event.tool_name,
                "resource": event.resource_key, "outcome": event.outcome, "timestamp": event.timestamp})
            for finding in findings:
                self.telemetry.add_event("secres.finding", {
                    "finding.id": finding.finding_id, "detection.type": finding.detection_type,
                    "severity": finding.severity, "level": finding.level})
            self.telemetry.record_event(event, event.outcome)

            codes = [f.legacy_code or f.detection_type for f in findings]
            self._write_log(raw, event, decision, codes, findings, source_port)
            return 200, {
                "decision": decision,
                "findings": codes,
                "event_id": event.event_id,
                "agent_id": event.agent_id,
                "session_id": event.session_id,
                "trace_id": trace_id,
                "finding_ids": [f.finding_id for f in findings],
            }

    @staticmethod
    def _decide(findings):
        if any(f.level == 1 for f in findings):
            return "refuser"  # comportement V0 : tout constat de niveau 1 refuse l'événement
        return "alerte" if findings else "autoriser"

    def _write_log(self, raw, event, decision, codes, findings, source_port):
        record = dict(raw)
        record.pop("token", None)
        record.update({
            "recu_le": now_iso(),
            "ip_source": event.source_ip,
            "port_source": source_port,
            "decision": decision,
            "findings": codes,
            "identite": {
                "agent_id": event.agent_id, "agent_role": event.agent_role, "session_id": event.session_id,
                "trace_id": event.trace_id, "event_id": event.event_id,
                "parent_event_id": event.parent_event_id, "verifie": event.identity_verified,
                "drapeaux": event.identity_flags,
            },
            "finding_ids": [f.finding_id for f in findings],
        })
        with self._log_lock, self._log_path.open("a", encoding="utf-8") as log:
            log.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    # ------------------------------------------------------------------ lecture (API)
    def list_findings(self, **filters):
        return [f.to_dict() for f in self.store.query(**filters)]

    def get_finding(self, finding_id):
        finding = self.store.get(finding_id)
        return finding.to_dict() if finding else None

    def metrics(self):
        return self.telemetry.metrics_snapshot()

    def traces(self, trace_id=None, limit=20):
        return self.telemetry.recent_traces(trace_id, limit)

    def agent_profile(self, agent_id):
        return self.engine.get_profile(agent_id)
