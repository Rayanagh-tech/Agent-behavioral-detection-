"""Agent de laboratoire synthétique (V1).

Conserve les scénarios V0 et ajoute : identité authentifiée (session + jeton signé), identifiants
d'événement chaînés (parent_event_id), traces OpenTelemetry (spans d'opération, spans enfants pour
les appels d'outils et accès aux ressources) et propagation du contexte W3C ``traceparent``.
Le rôle déclaré dans "acteur" reste envoyé comme en V0, mais le serveur ne lui fait pas confiance.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from opentelemetry.trace import SpanKind

from secres.telemetry import Telemetry, trace_id_hex

SCENARIOS = {
    "bon": [
        {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "credit"}, "acteur": {"role": "credit"}, "quantite": 2},
        {"type_evenement": "operation", "action": "accorder_credit", "ressource": {"type": "compte_credit", "id": "demo-001"}, "acteur": {"role": "credit"}, "approbation": {"requise": True, "approuvee": True}},
    ],
    "acces_non_autorise": [
        {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "rh"}, "acteur": {"role": "credit"}, "quantite": 1},
    ],
    "exfiltration": [
        {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "clients"}, "acteur": {"role": "assistance"}, "quantite": 120, "octets_transferes": 48000},
    ],
    "abus_outils": [
        {"type_evenement": "appel_outil", "action": "appel", "ressource": {"type": "outil", "id": "api_paiement"}, "acteur": {"role": "facturation"}, "quantite": 9},
    ],
    "contournement_validation": [
        {"type_evenement": "operation", "action": "rembourser", "ressource": {"type": "paiement", "id": "demo-paiement-001"}, "acteur": {"role": "facturation"}, "approbation": {"requise": True, "approuvee": False}},
    ],
    # --- Scénarios V1 (comportements dans le temps, identité) ---
    "exfiltration_graduelle": [
        {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "clients"}, "acteur": {"role": "assistance"}, "quantite": 18}
        for _ in range(8)
    ],
    "sequence_suspecte": [
        {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "clients"}, "acteur": {"role": "assistance"}, "quantite": 5},
        {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "clients"}, "acteur": {"role": "assistance"}, "quantite": 5},
        {"type_evenement": "operation", "action": "exporter", "ressource": {"type": "document", "id": "rapport-clients"}, "acteur": {"role": "assistance"}},
    ],
    "usurpation_role": [  # l'agent (rôle crédit) se déclare "rh" pour lire le jeu de données RH
        {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "rh"}, "acteur": {"role": "rh"}, "quantite": 1},
    ],
    "deviation_baseline": (
        [{"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "credit"}, "acteur": {"role": "credit"}, "quantite": 1 + (i % 3)}
         for i in range(24)]
        + [{"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "credit"}, "acteur": {"role": "credit"}, "quantite": 40},
           {"type_evenement": "operation", "action": "accorder_credit", "ressource": {"type": "compte_credit", "id": "demo-002"}, "acteur": {"role": "credit"}, "approbation": {"requise": True, "approuvee": True}}]
    ),
}

# Délai entre événements par scénario (secondes) ; défaut = AGENT_EVENT_DELAY (1 s comme en V0)
SCENARIO_DELAYS = {"exfiltration_graduelle": 0.3, "deviation_baseline": 0.2, "sequence_suspecte": 0.3}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _post(url, payload, headers, timeout=5):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except ValueError:
            return exc.code, {"error": "reponse_illisible"}


class AgentClient:
    def __init__(self, agent_id, secret, server_url, scenario, telemetry=None):
        self.agent_id = agent_id
        self.secret = secret
        self.server_url = server_url.rstrip("/")
        self.scenario = scenario
        self.telemetry = telemetry or Telemetry(f"agent-{agent_id}", span_dir=os.environ.get("SECRES_SPAN_DIR"))
        self.session_id = None
        self.token = None
        self.trace_id = None
        self.last_event_id = ""

    def open_session(self):
        """Initialisation : authentification auprès du serveur, qui attribue session_id, rôle et jeton."""
        with self.telemetry.start_span("agent.init", attributes={"agent.id": self.agent_id,
                                                                 "agent.scenario": self.scenario}):
            with self.telemetry.start_span("agent.session.open", kind=SpanKind.CLIENT):
                status, body = _post(self.server_url + "/session",
                                     {"agent_id": self.agent_id, "credential": self.secret},
                                     self.telemetry.inject())
            if status != 200:
                raise RuntimeError(f"ouverture de session refusée ({status}) : {body}")
            self.session_id, self.token = body["session_id"], body["token"]
            self.telemetry.add_event("agent.session.opened", {"session.id": self.session_id,
                                                              "agent.role": body["agent_role"]})
            return body

    def send(self, event):
        """Envoie un événement dans un span d'opération (+ span enfant pour outil / ressource)."""
        event = dict(event)
        etype = event.get("type_evenement", "inconnu")
        res = event.get("ressource", {})
        with self.telemetry.start_span("agent.operation", attributes={
                "agent.id": self.agent_id, "session.id": self.session_id, "event.type": etype,
                "event.action": event.get("action", ""), "resource.type": res.get("type", ""),
                "resource.id": res.get("id", "")}) as op_span:
            self.telemetry.add_event("agent.decision", {"action": event.get("action", ""), "resource": f"{res.get('type')}/{res.get('id')}"})
            child_name = {"appel_outil": "tool.call", "acces_donnees": "resource.access"}.get(etype, "operation.execute")
            child_attrs = {"tool.name": res.get("id", "")} if etype == "appel_outil" else {"resource.type": res.get("type", "")}
            with self.telemetry.start_span(child_name, kind=SpanKind.CLIENT, attributes=child_attrs) as call_span:
                self.trace_id = trace_id_hex(call_span)
                event.update({
                    "event_id": str(uuid.uuid4()),
                    "parent_event_id": self.last_event_id,
                    "agent_id": self.agent_id,
                    "session_id": self.session_id,
                    "trace_id": self.trace_id,
                    "horodatage_evenement": now_iso(),
                    "etiquette_scenario": self.scenario,
                })
                try:
                    status, body = _post(self.server_url + "/event", event,
                                         {"X-Session-Token": self.token or "", **self.telemetry.inject()})
                except (urllib.error.URLError, TimeoutError) as exc:
                    self.telemetry.mark_failure(call_span, "echec_envoi")
                    self.telemetry.mark_failure(op_span, "echec_envoi")
                    print(f"Échec d'envoi : {exc}", flush=True)
                    return None
                self.last_event_id = event["event_id"]
                decision = body.get("decision", "erreur")
                call_span.set_attribute("secres.decision", decision)
                op_span.set_attribute("secres.decision", decision)
                if status != 200 or decision == "refuser":
                    self.telemetry.mark_failure(call_span, decision)
                    self.telemetry.mark_failure(op_span, decision)
                print(json.dumps(body, ensure_ascii=False), flush=True)
                return body

    def run(self, events, delay):
        responses = []
        with self.telemetry.start_span("agent.run", attributes={"agent.id": self.agent_id,
                                                                "agent.scenario": self.scenario}):
            self.open_session()
            for event in events:
                responses.append(self.send(event))
                time.sleep(delay)
        return responses


def run_scenario(scenario, server_url, agent_id, secret, telemetry=None, delay=None):
    if scenario not in SCENARIOS:
        raise ValueError(f"Scénario inconnu : {scenario}")
    if delay is None:
        delay = SCENARIO_DELAYS.get(scenario, float(os.environ.get("AGENT_EVENT_DELAY", "1")))
    client = AgentClient(agent_id, secret, server_url, scenario, telemetry)
    return client.run([e.copy() for e in SCENARIOS[scenario]], delay), client


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "bon"
    if scenario not in SCENARIOS:
        raise SystemExit(f"Scénario inconnu : {scenario}")
    agent_id = os.environ.get("AGENT_ID", os.environ.get("HOSTNAME", "agent"))
    secret = os.environ.get("AGENT_SECRET", "")
    time.sleep(float(os.environ.get("AGENT_START_DELAY", "2")))
    try:
        run_scenario(scenario, os.environ.get("SERVER_URL", "http://server:8000"), agent_id, secret)
    except RuntimeError as exc:
        raise SystemExit(str(exc))
