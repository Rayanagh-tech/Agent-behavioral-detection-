"""Synthetic security-lab agent. Sends one evidence-rich event per scenario to server.py."""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

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
}


def send(event, sequence):
    #add metadata to event before sending to server
    event.update({
        #"id_evenement": f"{os.environ.get('AGENT_ID', 'agent')}-{sequence}",
        "horodatage_evenement": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        #"id_agent": os.environ.get("AGENT_ID", os.environ.get("HOSTNAME", "agent")),
        "etiquette_scenario": os.environ.get("SCENARIO", "inconnu"),
    })
    #encode event to JSON 
    body = json.dumps(event, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        os.environ.get("SERVER_URL", "http://server:8000") + "/event",
        data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        #send the request to the server and print the response
        with urllib.request.urlopen(request, timeout=5) as response:
            print(response.read().decode("utf-8"), flush=True)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Échec d'envoi : {exc}", flush=True)


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "bon"
    if scenario not in SCENARIOS:
        raise SystemExit(f"Scénario inconnu : {scenario}")
    time.sleep(2)
    for number, event in enumerate(SCENARIOS[scenario], start=1):
        send(event.copy(), number)
        time.sleep(1)
