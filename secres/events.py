"""Événement standardisé consommé par la télémétrie et par le moteur de détection."""
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

ID_PATTERN = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class StandardEvent:
    event_id: str
    parent_event_id: str
    timestamp: str
    received_at: float
    agent_id: str
    agent_role: str
    session_id: str
    trace_id: str
    span_id: str
    event_type: str
    action: str
    resource_type: str
    resource_id: str
    tool_name: str
    quantity: int
    bytes_transferred: int
    approval_required: object
    approval_granted: object
    scenario: str
    source_ip: str
    identity_verified: bool
    identity_flags: list = field(default_factory=list)
    outcome: str = "pending"

    @property
    def actor_key(self):
        """Clé de corrélation des activités : l'agent vérifié, sinon la source réseau."""
        return self.agent_id if self.identity_verified else f"unverified:{self.source_ip}"

    @property
    def resource_key(self):
        return f"{self.resource_type}/{self.resource_id}"

    def to_dict(self):
        return asdict(self)


def _checked_id(value, name, required=False):
    if value is None or value == "":
        if required:
            raise ValueError(f"{name}_obligatoire")
        return ""
    if not isinstance(value, str) or not ID_PATTERN.match(value):
        raise ValueError(f"{name}_invalide")
    return value


def _text(value, limit=128):
    return value[:limit] if isinstance(value, str) else ""


def normalize_event(raw, identity, trace_id, span_id, received_at=None, source_ip="", flags_extra=()):
    """Transforme l'événement brut envoyé par l'agent (format V0 + champs d'identité) en StandardEvent.

    Lève ValueError pour un événement structurellement invalide (HTTP 400, comme en V0).
    """
    if not isinstance(raw, dict):
        raise ValueError("evenement_doit_etre_un_objet")
    ressource = raw.get("ressource") if isinstance(raw.get("ressource"), dict) else {}
    approbation = raw.get("approbation") if isinstance(raw.get("approbation"), dict) else {}
    try:
        quantity = int(raw.get("quantite", 0))
        transferred = int(raw.get("octets_transferes", 0))
    except (TypeError, ValueError):
        raise ValueError("quantite_ou_octets_non_entier")
    flags = list(identity.flags) + list(flags_extra)
    if quantity < 0 or transferred < 0:
        flags.append("negative_quantity")
    event_type = _text(raw.get("type_evenement"))
    resource_type = _text(ressource.get("type"))
    resource_id = _text(ressource.get("id"))
    tool_name = _text(raw.get("outil")) or (resource_id if resource_type == "outil" else "")
    return StandardEvent(
        event_id=_checked_id(raw.get("event_id"), "event_id") or str(uuid.uuid4()),
        parent_event_id=_checked_id(raw.get("parent_event_id"), "parent_event_id"),
        timestamp=_text(raw.get("horodatage_evenement") or raw.get("timestamp"), 40) or now_iso(),
        received_at=received_at if received_at is not None else time.time(),
        agent_id=identity.agent_id,
        agent_role=identity.agent_role,
        session_id=identity.session_id,
        trace_id=trace_id,
        span_id=span_id,
        event_type=event_type,
        action=_text(raw.get("action")),
        resource_type=resource_type,
        resource_id=resource_id,
        tool_name=tool_name,
        quantity=quantity,
        bytes_transferred=transferred,
        approval_required=approbation.get("requise"),
        approval_granted=approbation.get("approuvee"),
        scenario=_text(raw.get("etiquette_scenario"), 64),
        source_ip=source_ip,
        identity_verified=identity.verified,
        identity_flags=flags,
    )
