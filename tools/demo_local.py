"""Démonstration locale sans Docker : démarre le serveur, exécute tous les scénarios, affiche les résultats.

Usage : python tools/demo_local.py [--log-dir DIR] [--port 8000] [--fast]
"""
import argparse
import json
import os
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import SCENARIOS, run_scenario  # noqa: E402
from secres.app import SecResApp  # noqa: E402
from server import make_server  # noqa: E402

SCENARIO_AGENTS = {
    "bon": "bon-agent",
    "acces_non_autorise": "non-authorise-agent",
    "exfiltration": "exfiltration-agent",
    "abus_outils": "abus-outils-agent",
    "contournement_validation": "contournement-validation-agent",
    "exfiltration_graduelle": "exfiltration-graduelle-agent",
    "sequence_suspecte": "sequence-suspecte-agent",
    "usurpation_role": "usurpation-role-agent",
    "deviation_baseline": "baseline-deviation-agent",
}


def get(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-dir", default=None)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--fast", action="store_true", help="délai minimal entre événements")
    args = parser.parse_args()
    log_dir = args.log_dir or tempfile.mkdtemp(prefix="secres-demo-")
    os.environ.setdefault("SECRES_SPAN_DIR", str(Path(log_dir) / "spans"))  # spans des agents -> même dossier que ceux du serveur
    app = SecResApp(log_dir=log_dir, signing_key="cle-de-demo-uniquement")
    server = make_server(app, "127.0.0.1", args.port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Serveur : {base}   journaux : {log_dir}\n")

    summary = {}
    for scenario in SCENARIOS:
        agent_id = SCENARIO_AGENTS[scenario]
        responses, client = run_scenario(scenario, base, agent_id, f"demo-secret-{agent_id}",
                                         delay=0.01 if args.fast else None)
        summary[scenario] = (agent_id, [r["decision"] for r in responses if r],
                             sorted({c for r in responses if r for c in r["findings"]}), client.trace_id)

    print("\n=== Résumé par scénario ===")
    for scenario, (agent_id, decisions, codes, trace_id) in summary.items():
        counts = {d: decisions.count(d) for d in sorted(set(decisions))}
        print(f"{scenario:26s} {agent_id:32s} décisions={counts} constats={codes} trace={trace_id[:8]}…")
    findings = get(base + "/findings?limit=1000")["findings"]
    print(f"\nFindings structurés : {len(findings)}   métriques : {len(get(base + '/metrics'))} instruments")
    server.shutdown()


if __name__ == "__main__":
    main()
