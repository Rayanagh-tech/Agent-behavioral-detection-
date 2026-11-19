"""Receives security-lab events, checks resource access, and writes JSONL logs."""
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOG_PATH = Path("/app/logs/evenements.jsonl")#docker Compose mounts the host logs folder at /app/logs in this container.
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
LOG_LOCK = threading.Lock() #prevent concurrent request threads from interleaving writes to the JSONL file
MAX_BODY_BYTES = 64 * 1024 #reject oversized requests before reading their body into memory


# Roles authorized for each resource ID, grouped by resource type
# A "*" entry applies to every resource ID of that type
# Keep the resource type and ID values in sync with those sent by agent.py
CONTROLES_ACCES = {
    "jeu_donnees": {
        "credit": {"credit"},
        "rh": {"rh"},
        "clients": {"assistance"},
    },
    "compte_credit": {
        "*": {"credit"},
    },
    "outil": {
        "api_paiement": {"facturation"},
    },
    "paiement": {
        "*": {"facturation"},
    },
    "document": {
        "*": {"assistance"},
    },
}


# timestamp the request in utc
def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def role_autorise(acteur, ressource):
    """Check whether the actor's role may use this resource; unknowns are denied."""
    if not isinstance(acteur, dict) or not isinstance(ressource, dict):
        return False
    
    # Read the role and resource identity from the event fields
    role = acteur.get("role")
    type_ressource = ressource.get("type")
    id_ressource = ressource.get("id")
    controles_type = CONTROLES_ACCES.get(type_ressource, {}) #get the list of who can access this type of resource, return empty dictionary if the resource type is unknown

    # Try an exact resource ID first, then the wildcard for this resource type.
    # An empty set means this resource is unknown, so access is denied by default.
    roles_autorises = controles_type.get(id_ressource, controles_type.get("*", set()))
    return isinstance(role, str) and role in roles_autorises #return true if the actor has access to this resource id


def evaluate(e):
    """Return a decision and findings derived from event evidence."""
    # Findings are evidence-based reasons to deny or flag the event.
    findings = []
    typ = e.get("type_evenement")
    acteur = e.get("acteur") or {}
    ressource = e.get("ressource") or {}
    approbation = e.get("approbation") or {}

    # Every event that names a resource must pass the resource's role ACL
    # Missing or unrecognized resource/role data also fails this check
    if not role_autorise(acteur, ressource):
        findings.append("acces_non_autorise")

    # Example exfiltration signals: at least 50 records, or a large transfer
    if typ == "acces_donnees" and ( (int(e.get("quantite", 0)) >= 50 or int(e.get("octets_transferes", 0) >= 10000)) ):
        findings.append("exfiltration_possible")

    # Example tool-abuse threshold: five or more calls in the reported quantity
    if typ == "appel_outil" and int(e.get("quantite", 0)) >= 5:
        findings.append("abus_outils_seuil_frequence")

    # Deny protected operations when approval is missing
    if typ == "operation" and approbation.get("requise") is True and  approbation.get("approuvee") is not True:
        findings.append("approbation_requise_absente_ou_contournee")

    # Any finding denies the event; an empty list means no rule found a problem.
    return {
        "decision": "refuser" if findings else "autoriser",
        "findings": findings,
    }


class Handler(BaseHTTPRequestHandler):
    # Send a JSON response to the agent that submitted the event.
    def send_json(self, status, value):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # Docker calls this endpoint to check whether the server is alive.
    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_error(404)

    # Agents submit their event records to this endpoint.
    def do_POST(self):
        if self.path != "/event":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                self.send_json(413, {"error": "taille_corps_invalide"})
                return

            event = json.loads(self.rfile.read(length))
            if not isinstance(event, dict):
                raise ValueError("evenement_doit_etre_un_objet")

            # Add receiver-side metadata; the source event fields remain available as evidence.
            event["recu_le"] = now_utc()
            event["ip_source"] = self.client_address[0]
            event["port_source"] = self.client_address[1]

            # Evaluate access permissions and security signals, then store the result in the log.
            evaluation = evaluate(event)
            event["decision"] = evaluation["decision"]
            event["findings"] = evaluation["findings"]

            # Write exactly one compact JSON object per line (JSONL), safely across threads.
            with LOG_LOCK:
                with LOG_PATH.open("a", encoding="utf-8") as log:
                    log.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                    log.flush()

            print(json.dumps(event, ensure_ascii=False), flush=True)
            # Return response that was successfully proccessed by server
            self.send_json(200, {
                #"id_evenement": event.get("id_evenement"),
                "decision": event["decision"],
                "findings": event["findings"],
            })
        # Invalid JSON or event values receive a client error instead of being logged as valid events.
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": "evenement_invalide", "detail": str(exc)})

    def log_message(self, fmt, *args):
        print("HTTP " + (fmt % args), flush=True)


if __name__ == "__main__":
    print("Listening on :8000", flush=True)
    # Listen on the container network interface and handle requests concurrently.
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
