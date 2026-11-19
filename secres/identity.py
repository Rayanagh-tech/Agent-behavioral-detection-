"""Identité d'agent avancée.

Principe : l'identité n'est JAMAIS déduite de ce que l'agent déclare. Elle est établie par des
composants de confiance côté serveur :

1. ``AgentRegistry``  : registre des agents autorisés (rôle attribué par l'administrateur,
   secret stocké uniquement sous forme de haché SHA-256).
2. ``SessionManager`` : ouvre une session après authentification et délivre un jeton signé
   HMAC-SHA256 (agent_id, rôle, session_id, expiration). Le serveur retient aussi la session.
3. ``IdentityService``: résout chaque événement entrant vers un ``IdentityContext`` vérifié et
   signale (flags) toute incohérence entre ce que l'agent déclare et ce que le serveur sait.
"""
import base64
import hashlib
import hmac
import json
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

UNKNOWN_AGENT = "unknown"
UNAUTHENTICATED_SESSION = "unauthenticated"
MAX_SEEN_EVENT_IDS = 10000


class IdentityError(Exception):
    """Échec d'authentification ou de validation d'identité ; ``reason`` est un code stable."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def hash_credential(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    role: str
    display_name: str
    credential_sha256: str


class AgentRegistry:
    def __init__(self, agents):
        self._agents = {}
        for agent_id, entry in agents.items():
            self._agents[agent_id] = AgentRecord(
                agent_id=agent_id,
                role=entry["role"],
                display_name=entry.get("display_name", entry["role"]),
                credential_sha256=entry["credential_sha256"],
            )

    @classmethod
    def from_file(cls, path):
        with Path(path).open(encoding="utf-8") as handle:
            return cls(json.load(handle)["agents"])

    def get(self, agent_id):
        return self._agents.get(agent_id) if isinstance(agent_id, str) else None

    def agent_ids(self):
        return list(self._agents)

    def authenticate(self, agent_id, credential):
        record = self.get(agent_id)
        expected = record.credential_sha256 if record else hash_credential("inconnu")
        supplied = hash_credential(credential) if isinstance(credential, str) else ""
        valid = hmac.compare_digest(expected, supplied)  # temps constant
        if record is None or not valid:
            raise IdentityError("authentification_refusee")
        return record


@dataclass
class Session:
    session_id: str
    agent_id: str
    agent_role: str
    issued_at: float
    expires_at: float
    trace_ids: set = field(default_factory=set)
    seen_event_ids: OrderedDict = field(default_factory=OrderedDict)


@dataclass
class IdentityContext:
    agent_id: str
    agent_role: str
    session_id: str
    verified: bool
    flags: list = field(default_factory=list)
    reason: str = ""

    @classmethod
    def unverified(cls, reason):
        return cls(UNKNOWN_AGENT, UNKNOWN_AGENT, UNAUTHENTICATED_SESSION, False,
                   ["identity_unverified"], reason)


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SessionManager:
    def __init__(self, registry, signing_key, ttl_seconds=3600, clock=time.time, max_sessions=10000):
        if not signing_key:
            raise ValueError("signing_key obligatoire")
        self.registry = registry
        self._key = signing_key if isinstance(signing_key, bytes) else signing_key.encode("utf-8")
        self.ttl = ttl_seconds
        self.clock = clock
        self.max_sessions = max_sessions
        self._sessions = OrderedDict()
        self._lock = threading.Lock()

    def _sign(self, payload_b64):
        return _b64(hmac.new(self._key, payload_b64.encode("ascii"), hashlib.sha256).digest())

    def open_session(self, agent_id, credential):
        record = self.registry.authenticate(agent_id, credential)
        now = self.clock()
        session = Session(
            session_id=str(uuid.uuid4()),
            agent_id=record.agent_id,
            agent_role=record.role,  # rôle issu du registre, pas de l'agent
            issued_at=now,
            expires_at=now + self.ttl,
        )
        payload = _b64(json.dumps(
            {"sid": session.session_id, "aid": session.agent_id, "role": session.agent_role,
             "exp": session.expires_at}, separators=(",", ":")).encode("utf-8"))
        token = payload + "." + self._sign(payload)
        with self._lock:
            self._sessions[session.session_id] = session
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        return session, token

    def verify(self, token):
        if not isinstance(token, str) or token.count(".") != 1:
            raise IdentityError("jeton_absent_ou_malforme")
        payload_b64, signature = token.split(".")
        if not hmac.compare_digest(self._sign(payload_b64), signature):
            raise IdentityError("signature_invalide")
        try:
            claims = json.loads(_unb64(payload_b64))
            session_id, agent_id, role, expires_at = claims["sid"], claims["aid"], claims["role"], claims["exp"]
        except (ValueError, KeyError, TypeError):
            raise IdentityError("jeton_malforme")
        if self.clock() >= expires_at:
            raise IdentityError("session_expiree")
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise IdentityError("session_inconnue")
        record = self.registry.get(agent_id)
        if record is None or record.role != role or session.agent_id != agent_id or session.agent_role != role:
            raise IdentityError("identite_incoherente_avec_registre")
        return session

    def revoke(self, session_id):
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def get(self, session_id):
        with self._lock:
            return self._sessions.get(session_id)

    def note_event(self, session, event_id, trace_id):
        """Enregistre event_id/trace_id pour la session ; renvoie True si l'event_id est un rejeu."""
        with self._lock:
            replay = event_id in session.seen_event_ids
            session.seen_event_ids[event_id] = True
            while len(session.seen_event_ids) > MAX_SEEN_EVENT_IDS:
                session.seen_event_ids.popitem(last=False)
            if len(session.trace_ids) < 1000:
                session.trace_ids.add(trace_id)
            return replay


class IdentityService:
    """Résout l'identité vérifiée d'un événement et détecte les déclarations incohérentes."""

    def __init__(self, sessions):
        self.sessions = sessions

    def resolve(self, token, claimed_agent_id=None, claimed_session_id=None, declared_role=None):
        try:
            session = self.sessions.verify(token)
        except IdentityError as exc:
            return IdentityContext.unverified(exc.reason), None
        ctx = IdentityContext(session.agent_id, session.agent_role, session.session_id, True)
        if claimed_agent_id is not None and claimed_agent_id != session.agent_id:
            ctx.flags.append("agent_id_mismatch")
        if claimed_session_id is not None and claimed_session_id != session.session_id:
            ctx.flags.append("session_id_mismatch")
        if declared_role is not None and declared_role != session.agent_role:
            ctx.flags.append("role_mismatch")  # l'agent déclare un rôle qui n'est pas le sien
        return ctx, session
