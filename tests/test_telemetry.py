import json

import pytest
from opentelemetry.trace import SpanKind, StatusCode

from conftest import secret_of
from secres.telemetry import Telemetry, sanitize_attributes


def by_name(telemetry, name):
    return [s for s in telemetry.ring.spans() if s.name == name]


def test_span_creation_and_attributes():
    t = Telemetry("svc")
    with t.start_span("agent.operation", attributes={"agent.id": "a1", "session.id": "s1"}):
        pass
    span = by_name(t, "agent.operation")[0]
    assert span.attributes["agent.id"] == "a1" and span.status.status_code == StatusCode.UNSET


def test_parent_child_relationship_and_failure_status():
    t = Telemetry("svc")
    with t.start_span("agent.operation") as parent:
        with t.start_span("tool.call", kind=SpanKind.CLIENT) as child:
            t.mark_failure(child, "refuser")
    p, c = by_name(t, "agent.operation")[0], by_name(t, "tool.call")[0]
    assert c.parent.span_id == p.context.span_id and c.context.trace_id == p.context.trace_id
    assert c.status.status_code == StatusCode.ERROR


def test_trace_context_propagates_between_two_components():
    agent, server = Telemetry("agent"), Telemetry("server")
    with agent.start_span("agent.operation"):
        with agent.start_span("tool.call", kind=SpanKind.CLIENT) as call:
            headers = agent.inject()
    assert "traceparent" in headers
    with server.start_span("gateway.request", parent=server.extract(headers), kind=SpanKind.SERVER):
        pass
    remote = by_name(server, "gateway.request")[0]
    assert remote.context.trace_id == call.get_span_context().trace_id
    assert remote.parent.span_id == call.get_span_context().span_id
    assert remote.parent.is_remote


def test_extract_is_case_insensitive_and_tolerates_garbage():
    t = Telemetry("svc")
    with t.start_span("x"):
        headers = {k.title(): v for k, v in t.inject().items()}
    with t.start_span("child", parent=t.extract(headers)):
        pass
    assert by_name(t, "child")[0].parent is not None
    with t.start_span("orphan", parent=t.extract({"traceparent": "invalide"})):
        pass
    assert by_name(t, "orphan")[0].parent is None


def test_sanitize_drops_sensitive_keys_and_bounds_values():
    clean = sanitize_attributes({"session.token": "abc", "password": "x", "api_key": "k", "Authorization": "Bearer z",
                                 "agent.id": "a", "n": 3, "long": "x" * 1000, "none": None})
    assert set(clean) == {"agent.id", "n", "long"} and len(clean["long"]) == 200


def test_gateway_trace_end_to_end_with_events_and_no_secrets(app):
    agent = Telemetry("agent-x")
    with agent.start_span("agent.operation"):
        with agent.start_span("resource.access", kind=SpanKind.CLIENT) as call:
            carrier = agent.inject()
            _, s = app.open_session({"agent_id": "bon-agent", "credential": secret_of("bon-agent")}, carrier, "10.0.0.4")
            ev = {"type_evenement": "acces_donnees", "action": "lecture",
                  "ressource": {"type": "jeu_donnees", "id": "credit"}, "acteur": {"role": "credit"}, "quantite": 1}
            _, res = app.handle_event(ev, {"X-Session-Token": s["token"], **carrier}, "10.0.0.4")
    trace_hex = format(call.get_span_context().trace_id, "032x")
    assert res["trace_id"] == trace_hex
    names = {sp.name for sp in app.telemetry.ring.spans()}
    assert {"gateway.session.open", "gateway.request", "identity.validate", "detection.process"} <= names
    gateway = by_name(app.telemetry, "gateway.request")[0]
    detection = by_name(app.telemetry, "detection.process")[0]
    assert detection.parent.span_id == gateway.context.span_id
    assert gateway.parent.span_id == call.get_span_context().span_id
    # événements structurés sur le span du gateway
    event = next(e for e in gateway.events if e.name == "secres.event")
    for key in ("agent.id", "agent.role", "session.id", "trace.id", "action", "resource", "outcome", "timestamp"):
        assert key in event.attributes
    assert event.attributes["agent.id"] == "bon-agent" and event.attributes["trace.id"] == trace_hex
    dump = json.dumps(app.telemetry.ring.as_dicts())
    assert s["token"] not in dump and secret_of("bon-agent") not in dump


def test_metrics_are_collected_with_low_cardinality_labels(app):
    _, s = app.open_session({"agent_id": "abus-outils-agent", "credential": secret_of("abus-outils-agent")}, {}, "1.1.1.1")
    tool = {"type_evenement": "appel_outil", "action": "appel", "ressource": {"type": "outil", "id": "api_paiement"},
            "acteur": {"role": "facturation"}, "quantite": 1}
    for _ in range(3):
        app.handle_event(dict(tool), {"X-Session-Token": s["token"]}, "1.1.1.1")
    app.handle_event({**tool, "quantite": 9}, {"X-Session-Token": s["token"]}, "1.1.1.1")  # refusé (>=5)
    m = app.metrics()
    for name in ("secres.agent.operations", "secres.tool.calls", "secres.resource.accesses",
                 "secres.detection.duration", "secres.detection.anomalies", "secres.agent.activity_rate"):
        assert name in m, name
    ops = {(p["attributes"]["outcome"]): p["value"] for p in m["secres.agent.operations"]["points"]}
    assert ops == {"success": 3, "denied": 1}
    tools = {p["attributes"]["outcome"]: p["value"] for p in m["secres.tool.calls"]["points"]}
    assert tools == {"success": 3, "denied": 9}
    assert m["secres.detection.duration"]["points"][0]["count"] == 4
    assert m["secres.detection.anomalies"]["points"][0]["attributes"]["detection_type"] == "tool_abuse_frequency"
    activity = {p["attributes"]["agent_role"]: p["value"] for p in m["secres.agent.activity_rate"]["points"]}
    assert activity["facturation"] == 4
    forbidden = {"agent_id", "session_id", "trace_id", "event_id", "agent.id", "session.id", "resource_id"}
    for metric in m.values():
        for point in metric["points"]:
            assert not forbidden & set(point["attributes"]), metric


def test_unknown_tool_names_are_bucketed_to_limit_cardinality(app):
    _, s = app.open_session({"agent_id": "abus-outils-agent", "credential": secret_of("abus-outils-agent")}, {}, "1.1.1.1")
    for i in range(30):
        app.handle_event({"type_evenement": "appel_outil", "action": "appel", "acteur": {"role": "facturation"},
                          "ressource": {"type": "outil", "id": f"outil-{i}"}, "quantite": 1},
                         {"X-Session-Token": s["token"]}, "1.1.1.1")
    labels = {p["attributes"]["tool_name"] for p in app.metrics()["secres.tool.calls"]["points"]}
    assert labels == {"other"}


def test_jsonl_span_export_to_directory(tmp_path):
    t = Telemetry("agent-demo", span_dir=tmp_path)
    with t.start_span("agent.run"):
        with t.start_span("tool.call"):
            pass
    lines = [json.loads(l) for l in (tmp_path / "spans-agent-demo.jsonl").read_text().splitlines()]
    assert {l["name"] for l in lines} == {"agent.run", "tool.call"}
    child = next(l for l in lines if l["name"] == "tool.call")
    root = next(l for l in lines if l["name"] == "agent.run")
    assert child["parent_span_id"] == root["span_id"] and child["trace_id"] == root["trace_id"]
