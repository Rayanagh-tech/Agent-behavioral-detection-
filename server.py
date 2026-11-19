"""Serveur SecRes V1 : reçoit les événements des agents, vérifie leur identité, applique la détection.

Routes :
  GET  /health                      état du service
  POST /session                     ouverture de session authentifiée (agent_id + credential)
  POST /event                       événement d'agent (en-têtes X-Session-Token et traceparent)
  GET  /findings[?agent_id=&session_id=&trace_id=&severity=&detection_type=&limit=]
  GET  /findings/<finding_id>
  GET  /metrics                     métriques OpenTelemetry (JSON)
  GET  /traces[?trace_id=&limit=]   spans récents groupés par trace
  GET  /agents/<agent_id>/profile   profil de comportement appris
Si SECRES_ADMIN_TOKEN est défini, les routes de lecture exigent « Authorization: Bearer <jeton> ».
"""
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from secres.app import SecResApp

MAX_BODY_BYTES = 64 * 1024  # rejette les requêtes trop volumineuses avant lecture du corps


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, value):
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_BYTES:
                return None, (413, {"error": "taille_corps_invalide"})
            return json.loads(self.rfile.read(length)), None

        def _admin_ok(self):
            if not app.admin_token:
                return True
            supplied = self.headers.get("Authorization", "")
            return hmac.compare_digest(supplied, "Bearer " + app.admin_token)

        def do_GET(self):
            url = urlparse(self.path)
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            if url.path == "/health":
                return self.send_json(200, {"status": "ok"})
            if not self._admin_ok():
                return self.send_json(401, {"error": "non_autorise"})
            try:
                limit = int(query.get("limit", 100))
            except ValueError:
                return self.send_json(400, {"error": "limit_invalide"})
            if url.path == "/findings":
                keys = ("agent_id", "session_id", "trace_id", "severity", "detection_type")
                filters = {k: query[k] for k in keys if k in query}
                return self.send_json(200, {"findings": app.list_findings(limit=limit, **filters)})
            if url.path.startswith("/findings/"):
                finding = app.get_finding(unquote(url.path.split("/", 2)[2]))
                return self.send_json(200, finding) if finding else self.send_json(404, {"error": "introuvable"})
            if url.path == "/metrics":
                return self.send_json(200, app.metrics())
            if url.path == "/traces":
                return self.send_json(200, {"traces": app.traces(query.get("trace_id"), min(limit, 200))})
            if url.path.startswith("/agents/") and url.path.endswith("/profile"):
                profile = app.agent_profile(unquote(url.path.split("/")[2]))
                return self.send_json(200, profile) if profile else self.send_json(404, {"error": "profil_inconnu"})
            self.send_error(404)

        def do_POST(self):
            if self.path not in ("/event", "/session"):
                self.send_error(404)
                return
            try:
                payload, error = self._read_json()
                if error:
                    return self.send_json(*error)
                ip, port = self.client_address[0], self.client_address[1]
                if self.path == "/session":
                    status, body = app.open_session(payload, dict(self.headers), ip)
                else:
                    status, body = app.handle_event(payload, dict(self.headers), ip, port)
                self.send_json(status, body)
                if self.path == "/event" and status == 200:
                    print(json.dumps({"event_id": body["event_id"], "agent_id": body["agent_id"],
                                      "decision": body["decision"], "findings": body["findings"]},
                                     ensure_ascii=False), flush=True)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self.send_json(400, {"error": "evenement_invalide", "detail": str(exc)})

        def log_message(self, fmt, *args):
            print("HTTP " + (fmt % args), flush=True)

    return Handler


def make_server(app, host="0.0.0.0", port=8000):
    return ThreadingHTTPServer((host, port), make_handler(app))


def build_app_from_env():
    signing_key = os.environ.get("SECRES_SIGNING_KEY")
    if not signing_key:
        print("SECRES_SIGNING_KEY absent : clé aléatoire (les sessions ne survivent pas au redémarrage).",
              file=sys.stderr, flush=True)
    return SecResApp(
        config_dir=os.environ.get("SECRES_CONFIG_DIR"),
        log_dir=Path(os.environ.get("SECRES_LOG_DIR", "logs")),
        signing_key=signing_key,
        admin_token=os.environ.get("SECRES_ADMIN_TOKEN"),
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"Listening on :{port}", flush=True)
    make_server(build_app_from_env(), "0.0.0.0", port).serve_forever()
