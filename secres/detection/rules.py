"""Niveau 1 - détection par règles (évaluation d'un événement + compteur d'opérations sensibles)."""
from collections import defaultdict, deque

from .findings import Finding

IDENTITY_FLAG_RULES = {
    "identity_unverified": ("identity_unverified", "critical",
                            "Événement sans identité vérifiable (jeton absent, invalide ou expiré)."),
    "role_mismatch": ("identity_spoofing", "critical",
                      "L'agent déclare un rôle différent de celui du registre de confiance."),
    "agent_id_mismatch": ("identity_spoofing", "high",
                          "L'agent_id déclaré ne correspond pas à celui de la session authentifiée."),
    "session_id_mismatch": ("identity_spoofing", "high",
                            "Le session_id déclaré ne correspond pas à la session authentifiée."),
    "replayed_event": ("replayed_event", "medium", "Un event_id déjà vu dans cette session a été rejoué."),
    "trace_mismatch": ("trace_mismatch", "low",
                       "Le trace_id déclaré diffère du contexte de trace propagé (traceparent)."),
}


class Level1Rules:
    def __init__(self, config, access_control):
        self.cfg = config["level1"]
        self.acl = access_control
        self.recommended = config["recommended_actions"]
        self._sensitive_history = defaultdict(deque)  # (acteur, action) -> horodatages

    def role_allowed(self, role, resource_type, resource_id):
        by_type = self.acl.get(resource_type, {})
        allowed = by_type.get(resource_id, by_type.get("*", []))
        return isinstance(role, str) and role in allowed

    def _finding(self, ev, detection_type, severity, description, evidence, legacy=""):
        return Finding(
            agent_id=ev.agent_id, session_id=ev.session_id, trace_id=ev.trace_id,
            detection_type=detection_type, severity=severity, description=description,
            evidence=evidence, level=1, event_id=ev.event_id, legacy_code=legacy,
            recommended_action=self.recommended.get(detection_type, self.recommended["default"]),
        )

    def evaluate(self, ev):
        cfg = self.cfg
        findings = []
        base = {"event_id": ev.event_id, "resource": ev.resource_key, "action": ev.action}

        for flag in ev.identity_flags:
            if flag in IDENTITY_FLAG_RULES:
                dtype, severity, text = IDENTITY_FLAG_RULES[flag]
                findings.append(self._finding(ev, dtype, severity, text, {**base, "flag": flag}))

        # Opération invalide : type/action inconnus ou quantités négatives
        valid_actions = cfg["valid_operations"].get(ev.event_type)
        if valid_actions is None or ev.action not in valid_actions or "negative_quantity" in ev.identity_flags:
            findings.append(self._finding(
                ev, "invalid_operation", "medium",
                f"Opération invalide : type '{ev.event_type}' / action '{ev.action}'.",
                {**base, "event_type": ev.event_type, "allowed_actions": valid_actions or []}))

        # Contrôle d'accès avec le rôle VÉRIFIÉ (jamais le rôle déclaré)
        if ev.identity_verified and not self.role_allowed(ev.agent_role, ev.resource_type, ev.resource_id):
            if ev.resource_type == "outil":
                findings.append(self._finding(
                    ev, "unauthorized_tool_usage", "high",
                    f"Le rôle '{ev.agent_role}' n'est pas autorisé à utiliser l'outil '{ev.resource_id}'.",
                    {**base, "verified_role": ev.agent_role}, legacy="acces_non_autorise"))
            else:
                findings.append(self._finding(
                    ev, "unauthorized_resource_access", "high",
                    f"Le rôle '{ev.agent_role}' n'est pas autorisé à accéder à {ev.resource_key}.",
                    {**base, "verified_role": ev.agent_role}, legacy="acces_non_autorise"))

        # Signaux V0 : exfiltration sur un seul événement
        if ev.event_type == "acces_donnees" and (
                ev.quantity >= cfg["single_read_max_records"] or ev.bytes_transferred >= cfg["single_read_max_bytes"]):
            findings.append(self._finding(
                ev, "data_exfiltration_suspected", "high",
                "Lecture volumineuse en une seule requête (nombre de fiches ou octets transférés élevé).",
                {**base, "quantity": ev.quantity, "bytes": ev.bytes_transferred,
                 "max_records": cfg["single_read_max_records"], "max_bytes": cfg["single_read_max_bytes"]},
                legacy="exfiltration_possible"))

        # Signal V0 : abus d'outil
        if ev.event_type == "appel_outil" and ev.quantity >= cfg["tool_call_quantity_threshold"]:
            findings.append(self._finding(
                ev, "tool_abuse_frequency", "high",
                f"Nombre d'appels d'outil élevé dans une seule requête ({ev.quantity}).",
                {**base, "tool": ev.tool_name, "quantity": ev.quantity,
                 "threshold": cfg["tool_call_quantity_threshold"]},
                legacy="abus_outils_seuil_frequence"))

        # Contournement d'approbation (V0) et action sensible sans métadonnée d'approbation
        if ev.event_type == "operation":
            if ev.approval_required is True and ev.approval_granted is not True:
                findings.append(self._finding(
                    ev, "approval_bypass", "high",
                    "Opération protégée exécutée sans l'approbation requise.",
                    {**base, "approval_required": True, "approval_granted": ev.approval_granted},
                    legacy="approbation_requise_absente_ou_contournee"))
            elif ev.action in cfg["sensitive_actions"] and ev.approval_required is None:
                findings.append(self._finding(
                    ev, "suspicious_action", "medium",
                    "Action sensible sans aucune métadonnée d'approbation.",
                    {**base, "sensitive_actions": cfg["sensitive_actions"]}))

        findings.extend(self._repeated_sensitive(ev, base))
        return findings

    def _repeated_sensitive(self, ev, base):
        rule = self.cfg["repeated_sensitive"]
        if ev.event_type != "operation" or ev.action not in self.cfg["sensitive_actions"]:
            return []
        history = self._sensitive_history[(ev.actor_key, ev.action)]
        history.append(ev.received_at)
        while history and ev.received_at - history[0] > rule["window_seconds"]:
            history.popleft()
        if len(history) >= rule["max_count"]:
            return [self._finding(
                ev, "repeated_sensitive_operations", "high",
                f"L'action sensible '{ev.action}' a été répétée {len(history)} fois en {rule['window_seconds']} s.",
                {**base, "count": len(history), "window_seconds": rule["window_seconds"],
                 "max_count": rule["max_count"]})]
        return []
