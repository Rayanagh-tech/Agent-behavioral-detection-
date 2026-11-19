SecRes-NetworkThreatDetection-V1 — Project analysis and execution guide


Your project is a Threat Detection and Security Monitoring system built with Python, detection rules, behavioral analysis, and OpenTelemetry instrumentation.

The goal is to detect suspicious agent activity, generate security findings, and expose monitoring information through telemetry.

I will separate this into four parts:
1. What your project contains and its architecture.
2. How agents and detection scenarios work.
3. How OpenTelemetry fits into the system.
4. How to run the project on Windows and validate it end to end.

OpenTelemetry is the observability layer, not the threat detection engine itself. Your detection engine evaluates events and rules; OpenTelemetry helps trace and monitor the execution of that process.

1. What is included in your project?

I inspected the public GitHub repository and its README. The project is a V1 extension of an earlier V0 implementation. 
GitHub+1

Project structure
Component	Responsibility
agent.py	Simulates security agents and their operations
server.py	Receives events and processes requests
secres/identity.py	Agent authentication, sessions and identity verification
secres/events.py	Standardized security events
secres/telemetry.py	OpenTelemetry traces and metrics
secres/app.py	Main application and API
secres/detection/	Behavioral detection engine
config/agents.json	Agent identity registry
config/access_control.json	Role-based access permissions
config/detection.json	Detection thresholds and configuration
tests/	Automated tests
tools/demo_local.py	Runs the complete demonstration
tools/trace_view.py	Displays distributed trace trees
legacy_v0/	Original V0 implementation

OpenTelemetry instruments the agents and server so that you can follow an operation from the agent to the gateway and then to the detection engine.

2. Agents and detection scenarios

Your project uses synthetic banking agents. These are simulated software agents, not actual autonomous AI agents or real network devices.

The README describes nine scenarios.

Five V0 scenarios
Scenario	What it simulates
bon	Normal authorized activity
acces_non_autorise	Unauthorized resource access
exfiltration	Suspicious bulk data extraction
abus_outils	Unauthorized or abusive tool usage
contournement_validation	Bypassing a required validation

Four additional V1 scenarios
01
Gradual exfiltration

An agent performs eight reads of 18 records. The system analyzes the cumulative behavior over a time window.



02
Suspicious sequence

An agent reads customer records and then performs an export. The sequence itself is suspicious.



03
Role impersonation

A credit agent declares itself as an HR agent. The system compares the declared identity with its trusted registry.



04
Behavioral baseline deviation

An agent performs 24 normal reads, then suddenly reads 40 records from a new resource. The system detects the deviation.




GitHub+1
How the detection engine works
- N1 — Rule-based detection: Detects explicitly forbidden actions, excessive quantities and repeated operations.
- N2 — Temporal detection: Analyzes event frequency, sequences and accumulated activity over time.
- N3 — Behavioral detection: Learns an agent's normal activity and identifies statistically unusual behavior.

The output is a structured finding containing:
- finding_id
- agent_id
- session_id
- trace_id
- detection_type
- severity
- description
- evidence
- recommended_action

Your engine supports three decisions:
Decision	Meaning
autoriser	Allow the operation
alerte	Allow with a security alert
refuser	Reject the operation

This is a useful architecture for a behavioral detection prototype.

3. OpenTelemetry: what exactly is implemented?
This is one of the most interesting parts of your V1.

OpenTelemetry provides observability across the agent-server workflow.
A. Distributed tracing

Your agent creates spans such as:
agent.run
 ├── agent.init
 ├── agent.session.open
 └── agent.operation
      ├── tool.call
      ├── resource.access
      └── operation.execute


The server creates corresponding spans:
gateway.request
 ├── identity.validate
 └── detection.process


The W3C traceparent header connects these operations using a common trace ID.

This allows you to investigate:
- Which agent generated an event?
- Which server request received it?
- Was its identity valid?
- Which detection rule was evaluated?
- What decision was returned?
- How long did detection take?
B. Metrics

Your implementation defines these metrics:
Metric	                 Purpose      
secres.agent.operations	Number of agent operations
secres.tool.calls	Tool invocation count
secres.resource.accesses	Resource access count
secres.agent.activity_rate	Agent activity rate
secres.detection.duration	Detection processing duration
secres.detection.anomalies	Detected anomalies
secres.identity.failures	Identity verification failures

An important security design choice: sensitive identifiers such as agent_id, session_id and trace_id are not used as metric labels. Secrets and authorization tokens are also filtered from telemetry.

C. Where to inspect telemetry
Your project exposes:
- GET /metrics
- GET /traces
- logs/spans/spans-<service>.jsonl
- tools/trace_view.py
Important distinction: Local JSONL tracing and JSON metrics are implemented. OTLP export is optional and requires an external OpenTelemetry Collector or compatible backend. It is not automatically provided by your project.














Pour la prochaine étape, je te conseille de faire évoluer SecRes V1 d'un simple prototype de détection comportementale vers un véritable mini-laboratoire SOC / Detection Engineering.

L'objectif n'est pas simplement d'ajouter Wazuh pour avoir un outil de plus. L'objectif est de reproduire le travail réel d'une ingénieure sécurité :

Générer des événements de sécurité réalistes.

Collecter et centraliser les logs.


Détecter les comportements suspects.

Corréler plusieurs événements.

Qualifier les alertes (faux positifs / vrais positifs).

Répondre à l'incident et conserver les preuves.

Mesurer la qualité de la détection.

Je te propose de construire cela progressivement, sans remplacer ton moteur SecRes existant.

1. Architecture cible : SecRes + Wazuh + Sysmon
Je recommande cette architecture :



Simulation d'attaques contrôlées

Agents Python · scénarios MITRE ATT&CK · activités Windows/Linux

Sysmon

Processus, connexions réseau, fichiers, registre Windows

SecRes agents

Identité, sessions, outils, événements comportementaux

Wazuh SIEM / XDR

Collecte · règles · alertes · inventaire · corrélation

SecRes Detection Engine

Corrélation comportementale · baseline · détection multi-événements

SOC Dashboard & Incident Response

Alertes · investigation · preuves · réponse · rapport

Pourquoi cette architecture ?

Wazuh apporte la collecte des événements système, les règles de détection, le suivi des vulnérabilités et la réponse active. 

Wazuh Documentation
+3

Sysmon apporte des événements Windows beaucoup plus proches de ce qu'un analyste SOC examine réellement : création de processus, connexions réseau et modifications système.

SecRes conserve sa valeur ajoutée : détecter les anomalies de comportement des agents IA, notamment les abus d'outils, les changements de rôle et l'exfiltration graduelle.

Ne remplace donc pas SecRes par Wazuh : fais-les travailler ensemble.



2. Faire évoluer la simulation : passer des scénarios fictifs aux exercices SOC
Actuellement, tes scénarios SecRes simulent surtout le comportement des agents bancaires. C'est utile pour tester ton moteur, mais insuffisant pour démontrer une pratique complète de Security Engineering.

Je te propose ces exercices, dans un environnement local isolé :

Sysmon - Sysinternals | Microsoft Learn

Scénario 1 — Suspicious Process Execution

Simuler le lancement d'un processus inhabituel dans une VM Windows. Collecter les événements Sysmon et créer une règle de détection.

MITRE ATT&CK : Execution · T1059 selon la technique testée

Response to SSH Attack Using Shuffle, Wazuh, and TheHive | FaresMorcy

Scénario 2 — Brute Force Authentication

Générer plusieurs échecs d'authentification SSH dans une VM Linux, détecter les tentatives répétées et identifier l'adresse source.

MITRE ATT&CK : Brute Force · T1110

File Integrity Monitoring with Wazuh SIEM Tool - DEV Community

Scénario 3 — File Integrity Monitoring

Modifier un fichier surveillé, détecter la modification, identifier l'heure et examiner les changements.

MITRE ATT&CK : Indicator Removal / File modification selon le cas



Scénario 4 — Network Intrusion Detection

Utiliser Suricata pour observer du trafic de laboratoire, détecter une activité réseau suspecte et envoyer les alertes vers ton système de supervision.

MITRE ATT&CK : Discovery / Command and Control selon le trafic testé

Dashboard Studio: Schedule This! | Splunk

Scénario 5 — AI Agent Abuse

Un agent autorisé tente d'utiliser un outil interdit, accède à une ressource inhabituelle ou essaie d'envoyer trop de données.

Détection SecRes : identity abuse · tool abuse · exfiltration

Pour les exercices, utilise uniquement des machines et données de laboratoire que tu contrôles. Le but est de produire des événements observables, pas de lancer des attaques sur un réseau réel.

3. Les outils que je recommande
N'installe pas tous les outils en même temps. Voici les priorités :

Outil

Utilité dans ton projet

Priorité

Wazuh

SIEM, collecte, alertes, FIM, réponse

Essentiel

Sysmon

Télémétrie Windows détaillée

Essentiel

MITRE ATT&CK

Cartographier les scénarios et détections

Essentiel

Atomic Red Team

Exécuter des tests contrôlés et reproductibles

Essentiel

Sigma

Écrire des règles de détection standardisées

Ensuite

Suricata

Détection réseau IDS

Ensuite

TheHive

Gestion des incidents et investigations

Plus tard

Quelques références utiles :

Documentation officielle Wazuh.

Atomic Red Team – documentation : tests contrôlés, prérequis, exécution et nettoyage.

Sigma – spécification des règles.

MITRE ATT&CK – Enterprise Matrix.

4. Le plan de développement que je suivrais
Phase 1 — Installer le véritable environnement SOC

Déployer Wazuh avec Docker.

Connecter une VM Windows avec Sysmon et Wazuh Agent.

Connecter une VM Linux avec Wazuh Agent.

Vérifier que les événements remontent réellement dans Wazuh.

Résultat : tu disposes de vrais endpoints supervisés.

Phase 2 — Créer des scénarios de simulation réalistes

Échecs d'authentification répétés.

Exécution de processus inhabituels.

Modification de fichiers surveillés.

Connexions réseau inhabituelles.

Abus d'outils par un agent IA.

Pour chaque scénario, documenter les événements attendus, les événements réellement collectés et les traces manquantes.

Phase 3 — Développer le Detection Engineering

Créer des règles personnalisées Wazuh.

Écrire des règles Sigma lorsque c'est pertinent.

Associer chaque règle à une technique MITRE ATT&CK.

Tester les faux positifs.

Ajuster les seuils et les fenêtres temporelles.

Résultat : tu ne fais pas que recevoir des alertes, tu sais concevoir et améliorer les détections.

Phase 4 — Connecter Wazuh à SecRes

Construire un petit service d'intégration qui récupère les alertes Wazuh et les transforme en événements normalisés pour SecRes.

Exemple :

Wazuh Alert
    |
    v
SecRes Event Normalizer
    |
    v
Behavioral Detection Engine
    |
    v
Correlation & Risk Scoring
    |
    v
SOC Dashboard
Conserve la provenance de chaque événement : wazuh, sysmon, secres ou suricata.

Phase 5 — Incident Response

Créer des niveaux de sévérité.

Générer un dossier d'incident.

Enregistrer les preuves et les événements associés.

Proposer une action de réponse.

Ajouter une validation humaine avant toute action destructive.

Tu pourras ensuite tester Wazuh Active Response dans ton laboratoire, avec des actions réversibles et contrôlées. 

Capabilities · Wazuh documentation
+1

Phase 6 — Évaluer la qualité du système

Mesurer :

Detection rate : proportion des tests détectés.

False positive rate : proportion des alertes incorrectes.

MTTD : temps moyen de détection.

MTTR : temps moyen de réponse.

ATT&CK coverage : techniques effectivement testées et détectées.

Ne considère pas une technique MITRE comme couverte simplement parce qu'une règle existe : il faut prouver qu'un test déclenche effectivement la détection.

6. Structure cible du repository
Je ferais évoluer ton projet progressivement vers cette organisation :
SecRes-NetworkThreatDetection-V1/
│
├── secres/
│   ├── identity/
│   ├── detection/
│   ├── correlation/
│   ├── response/
│   └── integrations/
│       ├── wazuh/
│       ├── sysmon/
│       └── suricata/
│
├── simulation/
│   ├── scenarios/
│   ├── windows/
│   ├── linux/
│   ├── ai_agents/
│   └── cleanup/
│
├── detection_rules/
│   ├── wazuh/
│   ├── sigma/
│   └── mitre_mapping/


















