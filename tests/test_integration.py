"""Tests d'intégration : identité + OpenTelemetry + détection, via HTTP réel (serveur local éphémère)."""
import importlib.util
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from agent import SCENARIOS, run_scenario
from conftest import secret_of
from secres.telemetry import Telemetry
from tools.demo_local import SCENARIO_AGENTS

V0_EXPECTED = {
    "bon": (["autoriser", "autoriser"], set()),
    "acces_non_autorise": (["refuser"], {"acces_non_autorise"}),
    "exfiltration": (["refuser"], {"exfiltration_possible"}),
    "abus_outils": (["refuser"], {"abus_outils_seuil_frequence"}),
    "contournement_validation": (["refuser"], {"approbation_requise_absente_ou_contournee"}),
}


def http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def run(base, scenario, telemetry=None):
    agent_id = SCENARIO_AGENTS[scenario]
    return run_scenario(scenario, base, agent_id, secret_of(agent_id), telemetry or Telemetry(f"agent-{agent_id}"), delay=0)


@pytest.mark.parametrize("scenario", list(V0_EXPECTED))
def test_v0_scenarios_keep_their_decisions_and_codes(http_server, scenario):
    base, _ = http_server
    responses, _ = run(base, scenario)
    decisions, codes = V0_EXPECTED[scenario]
    assert [r["decision"] for r in responses] == decisions
    assert {c for r in responses for c in r["findings"]} == codes


def test_differential_against_v0_evaluate(http_server, tmp_path):
    """Même décision et mêmes codes que le server.py de la V0 pour les événements du dépôt d'origine."""
    source = Path("legacy_v0/server.py").read_text(encoding="utf-8").replace("/app/logs/evenements.jsonl", (tmp_path / "v0.jsonl").as_posix())
    spec = importlib.util.spec_from_loader("legacy_v0_server", loader=None)
    legacy = importlib.util.module_from_spec(spec)
    exec(compile(source, "legacy_v0/server.py", "exec"), legacy.__dict__)
    base, _ = http_server
    for scenario in V0_EXPECTED:
        responses, _ = run(base, scenario)
        for raw, response in zip(SCENARIOS[scenario], responses):
            v0 = legacy.evaluate(dict(raw))
            assert response["decision"] == v0["decision"], scenario
            assert set(response["findings"]) == set(v0["findings"]), scenario


def test_new_scenarios_detected_with_expected_findings(http_server):
    base, app = http_server
    expect = {
        "exfiltration_graduelle": "gradual_exfiltration",
        "sequence_suspecte": "suspicious_sequence",
        "usurpation_role": "identity_spoofing",
        "deviation_baseline": "baseline_deviation",
    }
    for scenario, detection_type in expect.items():
        responses, client = run(base, scenario)
        _, body = http("GET", f"{base}/findings?trace_id={client.trace_id}")
        found = {f["detection_type"] for f in body["findings"]}
        assert detection_type in found, (scenario, found)
        for f in body["findings"]:  # corrélation identité / session / trace
            assert f["agent_id"] == SCENARIO_AGENTS[scenario]
            assert f["session_id"] == client.session_id and f["trace_id"] == client.trace_id


def test_role_spoofing_is_denied_using_the_verified_role(http_server):
    base, _ = http_server
    responses, _ = run(base, "usurpation_role")
    assert responses[0]["decision"] == "refuser"
    assert set(responses[0]["findings"]) == {"acces_non_autorise", "identity_spoofing"}


def test_unauthenticated_and_forged_requests_are_refused(http_server):
    base, app = http_server
    event = {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "credit"},
             "acteur": {"role": "credit"}, "quantite": 1, "agent_id": "bon-agent"}
    for headers in ({}, {"X-Session-Token": "a.b"}):
        status, body = http("POST", base + "/event", event, headers)
        assert status == 200 and body["decision"] == "refuser" and "identity_unverified" in body["findings"]
        assert body["agent_id"] == "unknown"  # l'identité déclarée n'est pas reprise
    status, _ = http("POST", base + "/session", {"agent_id": "bon-agent", "credential": "faux"})
    assert status == 401


def test_replayed_event_id_is_flagged(http_server):
    base, _ = http_server
    _, s = http("POST", base + "/session", {"agent_id": "bon-agent", "credential": secret_of("bon-agent")})
    ev = {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "credit"},
          "acteur": {"role": "credit"}, "quantite": 1, "event_id": "evt-rejoue"}
    h = {"X-Session-Token": s["token"]}
    assert http("POST", base + "/event", ev, h)[1]["decision"] == "autoriser"
    again = http("POST", base + "/event", ev, h)[1]
    assert "replayed_event" in again["findings"] and again["decision"] == "refuser"


def test_malformed_events_get_400(http_server):
    base, _ = http_server
    assert http("POST", base + "/event", {"quantite": "beaucoup"})[0] == 400
    assert http("POST", base + "/event", ["pas", "un", "objet"])[0] == 400
    assert http("POST", base + "/event", {"event_id": "contient des espaces!"})[0] == 400


def test_full_trace_agent_to_gateway_to_detection(http_server):
    """Une seule trace relie agent.run -> agent.operation -> tool.call -> gateway.request -> detection.process."""
    base, app = http_server
    agent_t = Telemetry("agent-abus-outils-agent")
    _, client = run(base, "abus_outils", agent_t)
    agent_spans = {s.name: s for s in agent_t.ring.spans()}
    server_spans = {s.name: s for s in app.telemetry.ring.spans() if s.context.trace_id == agent_spans["tool.call"].context.trace_id}
    assert {"agent.run", "agent.init", "agent.session.open", "agent.operation", "tool.call"} <= set(agent_spans)
    assert {"gateway.request", "identity.validate", "detection.process"} <= set(server_spans)
    chain = [("agent.operation", "agent.run"), ("tool.call", "agent.operation")]
    for child, parent in chain:
        assert agent_spans[child].parent.span_id == agent_spans[parent].context.span_id
    assert server_spans["gateway.request"].parent.span_id == agent_spans["tool.call"].context.span_id
    assert server_spans["detection.process"].parent.span_id == server_spans["gateway.request"].context.span_id
    assert client.trace_id == format(agent_spans["tool.call"].context.trace_id, "032x")
    assert agent_spans["tool.call"].status.status_code.name == "ERROR"  # opération refusée = échec


def test_events_in_a_scenario_are_chained_with_parent_event_id(http_server):
    base, app = http_server
    run(base, "bon")
    log = [json.loads(l) for l in open(app.log_dir / "evenements.jsonl", encoding="utf-8")]
    first, second = log[-2]["identite"], log[-1]["identite"]
    assert first["parent_event_id"] == "" and second["parent_event_id"] == first["event_id"]
    assert first["trace_id"] == second["trace_id"] and first["session_id"] == second["session_id"]


def test_api_endpoints_findings_metrics_traces_profile(http_server):
    base, app = http_server
    _, client = run(base, "acces_non_autorise")
    _, listing = http("GET", f"{base}/findings?agent_id=non-authorise-agent&severity=high")
    finding = listing["findings"][0]
    assert http("GET", f"{base}/findings/{finding['finding_id']}")[1] == finding
    assert http("GET", f"{base}/findings/inexistant")[0] == 404
    assert "secres.agent.operations" in http("GET", base + "/metrics")[1]
    traces = http("GET", f"{base}/traces?trace_id={client.trace_id}")[1]["traces"]
    assert traces and traces[0]["trace_id"] == client.trace_id and traces[0]["span_count"] >= 3
    status, profile = http("GET", base + "/agents/non-authorise-agent/profile")
    assert status == 200 and profile["established"] is False and profile["events_observed"] == 0  # événement refusé : non appris
    assert http("GET", base + "/agents/agent-inconnu/profile")[0] == 404
    assert http("GET", base + "/health")[1] == {"status": "ok"}


def test_admin_token_protects_read_api(tmp_path):
    from secres.app import SecResApp
    from server import make_server
    import threading
    app = SecResApp(log_dir=tmp_path, signing_key="k", admin_token="jeton-admin-test")
    server = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert http("GET", base + "/findings")[0] == 401
        assert http("GET", base + "/findings", headers={"Authorization": "Bearer jeton-admin-test"})[0] == 200
        assert http("GET", base + "/health")[0] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_jsonl_logs_never_contain_tokens_or_secrets(http_server):
    base, app = http_server
    _, client = run(base, "bon")
    blob = "".join(p.read_text() for p in app.log_dir.rglob("*.jsonl"))
    assert blob  # événements (et spans éventuels) bien écrits
    assert client.token not in blob and secret_of("bon-agent") not in blob
