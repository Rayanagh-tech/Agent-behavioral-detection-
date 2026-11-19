# SecRes-NetworkThreatDetection V1

Prototype de surveillance de sécurité pour agents bancaires **synthétiques** (aucune donnée ni identifiant réel).
La V1 ajoute trois améliorations à la V0, sans retirer de fonctionnalité :

1. **Identité d'agent avancée** : registre de confiance, sessions, jetons signés, événements standardisés (`agent_id`, `agent_role`, `session_id`, `trace_id`, `event_id`, `timestamp`, `parent_event_id`).
2. **Télémétrie OpenTelemetry** : traces distribuées (propagation W3C `traceparent`), événements structurés, métriques à faible cardinalité.
3. **Moteur de détection comportementale** : règles (N1), fenêtres de temps (N2), baselines par agent (N3), findings structurés exposés par API.

Architecture : [docs/architecture.md](docs/architecture.md) · [docs/architecture.svg](docs/architecture.svg).
La V0 d'origine est conservée telle quelle dans `legacy_v0/`.

## Arborescence
```
agent.py  server.py  Dockerfile  docker-compose.yml  requirements*.txt
secres/            identity.py  events.py  telemetry.py  app.py  config.py  detection/{rules,windows,baseline,engine,findings}.py
config/            agents.json  access_control.json  detection.json
tests/             68 tests pytest        tools/  demo_local.py  trace_view.py
legacy_v0/         agent.py, server.py, Dockerfile, docker-compose.yml de la V0 (inchangés)
simulateur-local.html   simulateur V0 (inchangé)
```

## Démarrage rapide (sans Docker)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                     # lance les 68 tests
python tools/demo_local.py --fast --log-dir logs     # serveur + 9 scénarios, résumé final
python tools/trace_view.py logs/spans --last 2       # arbre des traces agent + serveur
```

Serveur seul + un agent :
```bash
SECRES_SIGNING_KEY=dev SECRES_LOG_DIR=logs python server.py &
SERVER_URL=http://127.0.0.1:8000 AGENT_ID=exfiltration-agent AGENT_SECRET=demo-secret-exfiltration-agent \
  AGENT_START_DELAY=0 SECRES_SPAN_DIR=logs/spans python agent.py exfiltration
curl -s localhost:8000/findings | python -m json.tool
curl -s localhost:8000/metrics  | python -m json.tool
curl -s localhost:8000/traces   | python -m json.tool
```

## Avec Docker Compose
```bash
docker compose up --build        # serveur 172.28.0.3 + 9 agents (IP 172.28.0.4 à .12)
curl localhost:8000/findings
python tools/trace_view.py logs/spans
docker compose down
```
Les secrets de démonstration sont `demo-secret-<agent_id>` (synthétiques). La clé de signature `SECRES_SIGNING_KEY` du compose est une valeur de démo : à remplacer hors laboratoire.

## API du serveur
| Route | Description |
|---|---|
| `GET /health` | état |
| `POST /session` | `{agent_id, credential}` -> `session_id`, `agent_role`, `token` |
| `POST /event` | événement V0 + champs d'identité ; en-têtes `X-Session-Token`, `traceparent`. Réponse V0 (`decision`, `findings`) enrichie de `event_id`, `agent_id`, `session_id`, `trace_id`, `finding_ids` |
| `GET /findings` | filtres `agent_id`, `session_id`, `trace_id`, `severity`, `detection_type`, `limit` |
| `GET /findings/<id>` | un finding |
| `GET /metrics` | métriques OpenTelemetry (JSON) |
| `GET /traces` | spans récents par trace (`trace_id`, `limit`) |
| `GET /agents/<id>/profile` | profil de comportement appris |

`SECRES_ADMIN_TOKEN` (optionnel) protège les routes GET (hors `/health`) par `Authorization: Bearer`.

Finding : `finding_id, agent_id, session_id, trace_id, detection_type, severity, description, evidence, timestamp, recommended_action` (+ `level`, `event_id`, `legacy_code`).
Décisions : `refuser` (finding de niveau 1, comme en V0), `alerte` (niveaux 2-3 seulement), `autoriser`.

## Identité : modèle de confiance
- L'agent s'authentifie avec un secret ; seul son haché SHA-256 est dans `config/agents.json`.
- Le **rôle vient du registre**, jamais de `acteur.role`. Un rôle, `agent_id` ou `session_id` déclaré différemment produit un finding `identity_spoofing` (critique/élevé) ; le contrôle d'accès utilise le rôle vérifié.
- Sans jeton valide, l'événement est refusé (`identity_unverified`), attribué à `unknown`, et corrélé par IP source.
- `event_id` rejoué dans une session -> `replayed_event` ; `trace_id` déclaré différent du `traceparent` -> `trace_mismatch`.

## Télémétrie
- Spans agent : `agent.run` > `agent.init` > `agent.session.open` ; `agent.operation` > `tool.call` / `resource.access` / `operation.execute`.
- Spans serveur (enfants via `traceparent`) : `gateway.session.open`, `gateway.request` > `identity.validate`, `detection.process`.
- Span events : `secres.event`, `secres.finding`, `agent.decision`, `agent.session.opened`. Opération refusée = span en `ERROR`.
- Métriques : `secres.agent.operations`, `secres.tool.calls`, `secres.resource.accesses`, `secres.agent.activity_rate` (gauge/min par rôle), `secres.detection.duration` (ms), `secres.detection.anomalies`, `secres.identity.failures`. Étiquettes limitées (rôle, type d'événement, issue, type de ressource, outil connu sinon `other`, type/sévérité de détection). Jamais d'agent_id, session_id, trace_id ni event_id.
- Aucun jeton, secret ni en-tête d'autorisation dans les spans ou journaux (filtre `sanitize_attributes`).
- Accès local : `/metrics`, `/traces`, `logs/spans/spans-<service>.jsonl`, `tools/trace_view.py`. Export OTLP optionnel : `pip install -r requirements-otlp.txt` puis `OTEL_EXPORTER_OTLP_ENDPOINT=http://hote:4318` (aucun backend n'est fourni ni imposé).

## Configuration de la détection (`config/detection.json`)
Tous les seuils sont externes : `level1` (volumes unitaires V0, actions sensibles, répétition), `time_window` (lectures, fiches clients, appels paiement, fréquence par outil, exfiltration graduelle, séquences déclaratives), `baseline` (`min_events`, `z_threshold`, `min_std`, fenêtre de débit), `cooldown_seconds` (anti-inondation). `SECRES_CONFIG_DIR` permet de pointer un autre dossier.

## Scénarios
V0 (inchangés) : `bon`, `acces_non_autorise`, `exfiltration`, `abus_outils`, `contournement_validation`.
V1 : `exfiltration_graduelle` (8 lectures de 18 fiches), `sequence_suspecte` (lecture clients puis export), `usurpation_role` (agent crédit se déclarant `rh`), `deviation_baseline` (24 lectures normales puis quantité 40 et nouvelle ressource).

## Ce qui a été testé (exécution réelle)
`python -m pytest -q` -> **68 passed** (identité 16, télémétrie 9, détection 27, intégration 16 ; ~8 s).
- Identité : unicité des agent_id/session_id, jetons falsifiés/expirés/révoqués, rôle issu du registre, agents simultanés (4 threads x 25 événements sans mélange d'identité), corrélation de trace.
- Télémétrie : création de spans, relations parent-enfant, propagation entre deux composants, événements, métriques, étiquettes à faible cardinalité, absence de secrets, export JSONL.
- Détection : accès/outil non autorisés, lectures excessives, appels répétés, séquences, exfiltration graduelle, déviation de baseline, trafic normal sans alerte, seuils pilotés par la configuration, anti-inondation.
- Régression V0 : test différentiel contre le `server.py` d'origine (`legacy_v0/`) sur les 5 scénarios (mêmes décisions et mêmes codes).
- Contrôle de sensibilité : en forçant volontairement un mauvais rôle dans la règle d'ACL, 16 tests échouent ; ils repassent après restauration.
- Démo locale (`tools/demo_local.py`) : les 9 scénarios donnent les décisions attendues ; une trace unique relie agent et serveur.
- Simulation du contenu de l'image Docker (dossier vierge avec uniquement les fichiers copiés par le `Dockerfile`) : serveur + agent fonctionnent ; un secret erroné donne un refus 401.
- `docker compose config` valide la syntaxe du compose.

## Ce qui n'est pas vérifié / limites
- **`docker compose up --build` n'a pas été exécuté** : pas de démon Docker dans l'environnement de développement. Seules la syntaxe du compose et la simulation du contenu de l'image ont été contrôlées. À valider chez vous.
- L'export OTLP n'a pas été testé (aucun collecteur disponible).
- État en mémoire : baselines, sessions et fenêtres sont perdues au redémarrage (les journaux JSONL restent). Le moteur est mono-processus.
- Les seuils fournis sont des valeurs de départ pour des données synthétiques ; un agent « support » qui lit des fiches clients à très haute cadence (ex. toutes les 3 s pendant plusieurs minutes) déclenche volontairement `gradual_exfiltration`. À ajuster avec du trafic réel.
- Le journal `evenements.jsonl` garde le format V0, augmenté d'un bloc `identite`. `simulateur-local.html` simule toujours les règles V0 uniquement.
- Pas de TLS ni de limitation de débit : prototype de laboratoire. Les identifiants de ressource (noms de jeux de données de démo) figurent dans les spans ; à hacher si ce sont de vrais identifiants clients.
- Hors périmètre, comme demandé : Wazuh, Prometheus, Grafana, détection d'injection indirecte.
