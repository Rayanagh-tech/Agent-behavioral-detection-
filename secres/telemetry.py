"""Télémétrie OpenTelemetry : traces, événements structurés et métriques.

Cette couche est volontairement séparée de la logique de détection. Les fournisseurs
(TracerProvider / MeterProvider) sont créés par instance et non globaux, ce qui permet à
plusieurs composants (serveur, agents) de coexister dans un même processus, notamment en test.
Aucun jeton, secret ou charge utile n'est enregistré ; les métriques n'utilisent que des
étiquettes à faible cardinalité (rôle, type d'événement, issue, type de ressource, outil connu).
"""
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.metrics import Observation
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.trace import SpanKind, Status, StatusCode
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

log = logging.getLogger("secres.telemetry")
SENSITIVE_KEY = re.compile(r"secret|token|password|credential|authorization|api[_-]?key|cookie", re.I)
PROPAGATOR = TraceContextTextMapPropagator()


def sanitize_attributes(attributes):
    """Supprime les clés sensibles et ne garde que des valeurs primitives bornées."""
    clean = {}
    for key, value in (attributes or {}).items():
        if SENSITIVE_KEY.search(key) or value is None:
            continue
        if isinstance(value, (bool, int, float)):
            clean[key] = value
        else:
            clean[key] = str(value)[:200]
    return clean


def trace_id_hex(span):
    return format(span.get_span_context().trace_id, "032x")


def span_id_hex(span):
    return format(span.get_span_context().span_id, "016x")


def _span_to_dict(span, service):
    ctx = span.get_span_context()
    parent = span.parent
    return {
        "trace_id": format(ctx.trace_id, "032x"),
        "span_id": format(ctx.span_id, "016x"),
        "parent_span_id": format(parent.span_id, "016x") if parent else None,
        "name": span.name,
        "service": service,
        "kind": span.kind.name,
        "start_ns": span.start_time,
        "duration_ms": round((span.end_time - span.start_time) / 1e6, 3),
        "status": span.status.status_code.name,
        "attributes": dict(span.attributes or {}),
        "events": [{"name": e.name, "attributes": dict(e.attributes or {})} for e in span.events],
    }


class RingSpanExporter(SpanExporter):
    """Conserve les derniers spans en mémoire (API /traces et tests)."""

    def __init__(self, service, max_spans=2000):
        self.service = service
        self._spans = deque(maxlen=max_spans)
        self._lock = threading.Lock()

    def export(self, spans):
        with self._lock:
            self._spans.extend(spans)
        return SpanExportResult.SUCCESS

    def spans(self):
        with self._lock:
            return list(self._spans)

    def as_dicts(self):
        return [_span_to_dict(s, self.service) for s in self.spans()]

    def shutdown(self):
        pass


class JsonlSpanExporter(SpanExporter):
    """Écrit un span JSON par ligne dans <dir>/spans-<service>.jsonl (visualisable avec tools/trace_view.py)."""

    def __init__(self, directory, service):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", service)
        self.path = directory / f"spans-{safe}.jsonl"
        self.service = service
        self._lock = threading.Lock()

    def export(self, spans):
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            for span in spans:
                handle.write(json.dumps(_span_to_dict(span, self.service), ensure_ascii=False,
                                        separators=(",", ":")) + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass


class Telemetry:
    def __init__(self, service_name, span_dir=None, otlp_endpoint=None, known_tools=(), max_spans=2000):
        self.service_name = service_name
        resource = Resource.create({"service.name": service_name})
        self.tracer_provider = TracerProvider(resource=resource)
        self.ring = RingSpanExporter(service_name, max_spans)
        self.tracer_provider.add_span_processor(SimpleSpanProcessor(self.ring))
        if span_dir:
            self.tracer_provider.add_span_processor(
                SimpleSpanProcessor(JsonlSpanExporter(span_dir, service_name)))
        otlp_endpoint = otlp_endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        metric_readers = []
        self.metric_reader = InMemoryMetricReader()
        metric_readers.append(self.metric_reader)
        if otlp_endpoint:
            self._add_otlp(otlp_endpoint, metric_readers)
        self.meter_provider = MeterProvider(resource=resource, metric_readers=metric_readers)
        self.tracer = self.tracer_provider.get_tracer("secres")
        self._known_tools = set(known_tools)
        self._activity = defaultdict(deque)  # rôle -> horodatages récents (débit d'activité)
        self._activity_lock = threading.Lock()
        self._create_instruments()

    def _add_otlp(self, endpoint, metric_readers):
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError:
            log.warning("OTEL_EXPORTER_OTLP_ENDPOINT défini mais exporter OTLP absent "
                        "(pip install -r requirements-otlp.txt) : export OTLP désactivé.")
            return
        base = endpoint.rstrip("/")
        self.tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=base + "/v1/traces")))
        metric_readers.append(PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=base + "/v1/metrics")))

    # ------------------------------------------------------------------ métriques
    def _create_instruments(self):
        meter = self.meter_provider.get_meter("secres")
        self.operations = meter.create_counter("secres.agent.operations", unit="1",
                                               description="Opérations d'agents traitées")
        self.tool_calls = meter.create_counter("secres.tool.calls", unit="1", description="Appels d'outils")
        self.resource_access = meter.create_counter("secres.resource.accesses", unit="1",
                                                    description="Accès aux ressources par type")
        self.anomalies = meter.create_counter("secres.detection.anomalies", unit="1",
                                              description="Anomalies détectées")
        self.identity_failures = meter.create_counter("secres.identity.failures", unit="1",
                                                      description="Échecs de vérification d'identité")
        self.detection_duration = meter.create_histogram("secres.detection.duration", unit="ms",
                                                         description="Durée du traitement de détection")
        meter.create_observable_gauge("secres.agent.activity_rate", callbacks=[self._activity_callback],
                                      unit="1/min", description="Événements par minute et par rôle (60 s glissantes)")

    def _activity_callback(self, _options):
        now = time.time()
        with self._activity_lock:
            observations = []
            for role, stamps in self._activity.items():
                while stamps and now - stamps[0] > 60:
                    stamps.popleft()
                observations.append(Observation(len(stamps), {"agent_role": role}))
        return observations

    def tool_label(self, tool_name):
        return tool_name if tool_name in self._known_tools else "other"

    def record_event(self, event, outcome):
        """Métriques d'une opération d'agent. Étiquettes : rôle, type, issue, type de ressource, outil connu."""
        role = event.agent_role if event.identity_verified else "unverified"
        self.operations.add(1, {"agent_role": role, "event_type": event.event_type or "invalid",
                                "outcome": outcome})
        self.resource_access.add(1, {"resource_type": event.resource_type or "unknown", "agent_role": role})
        if event.event_type == "appel_outil":
            self.tool_calls.add(max(1, event.quantity), {"tool_name": self.tool_label(event.tool_name),
                                                         "outcome": outcome})
        with self._activity_lock:
            stamps = self._activity[role]
            stamps.append(time.time())
            if len(stamps) > 10000:
                stamps.popleft()

    def record_detection(self, duration_ms, findings):
        self.detection_duration.record(duration_ms)
        for finding in findings:
            self.anomalies.add(1, {"detection_type": finding.detection_type, "severity": finding.severity})

    def record_identity_failure(self, reason):
        self.identity_failures.add(1, {"reason": reason})

    def metrics_snapshot(self):
        """Instantané JSON lisible de toutes les métriques (API GET /metrics)."""
        data = self.metric_reader.get_metrics_data()
        out = {}
        if data is None:
            return out
        for resource_metric in data.resource_metrics:
            for scope_metric in resource_metric.scope_metrics:
                for metric in scope_metric.metrics:
                    points = []
                    for point in metric.data.data_points:
                        entry = {"attributes": dict(point.attributes or {})}
                        if hasattr(point, "value"):
                            entry["value"] = point.value
                        else:  # histogramme
                            entry.update({"count": point.count, "sum": round(point.sum, 4),
                                          "min": point.min, "max": point.max})
                        points.append(entry)
                    out[metric.name] = {"description": metric.description, "unit": metric.unit, "points": points}
        return out

    # ------------------------------------------------------------------ traces
    def start_span(self, name, parent=None, kind=SpanKind.INTERNAL, attributes=None):
        """Context manager : span courant (enfant du span courant, ou de ``parent`` s'il est fourni)."""
        return self.tracer.start_as_current_span(
            name, context=parent, kind=kind, attributes=sanitize_attributes(attributes))

    @staticmethod
    def inject(carrier=None):
        """Injecte le contexte de trace courant (en-tête W3C ``traceparent``) dans ``carrier``."""
        carrier = {} if carrier is None else carrier
        PROPAGATOR.inject(carrier)
        return carrier

    @staticmethod
    def extract(headers):
        """Extrait un contexte de trace depuis des en-têtes HTTP (insensible à la casse)."""
        carrier = {k.lower(): v for k, v in dict(headers).items()}
        return PROPAGATOR.extract(carrier, context=Context())

    @staticmethod
    def add_event(name, attributes=None):
        """Événement structuré attaché au span courant."""
        span = trace.get_current_span()
        span.add_event(name, sanitize_attributes(attributes))

    @staticmethod
    def mark_failure(span, description):
        span.set_status(Status(StatusCode.ERROR, description))

    def recent_traces(self, trace_id=None, limit=20):
        spans = self.ring.as_dicts()
        grouped = defaultdict(list)
        for span in spans:
            if trace_id is None or span["trace_id"] == trace_id:
                grouped[span["trace_id"]].append(span)
        traces = [{"trace_id": tid, "span_count": len(items), "spans": items} for tid, items in grouped.items()]
        return traces[-max(1, min(limit, 200)):]

    def shutdown(self):
        self.tracer_provider.shutdown()
        self.meter_provider.shutdown()
