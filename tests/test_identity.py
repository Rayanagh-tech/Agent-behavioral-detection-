import json
import threading

import pytest

from conftest import secret_of
from secres.identity import (AgentRegistry, IdentityError, IdentityService, SessionManager, hash_credential)


@pytest.fixture
def registry():
    return AgentRegistry.from_file("config/agents.json")


@pytest.fixture
def sessions(registry, clock):
    return SessionManager(registry, "cle-de-test", ttl_seconds=60, clock=clock)


def test_registry_agent_ids_are_unique_and_roles_assigned(registry):
    ids = registry.agent_ids()
    assert len(ids) == len(set(ids)) >= 9
    assert registry.get("bon-agent").role == "credit"
    assert registry.get("exfiltration-agent").role == "assistance"


def test_registry_never_stores_plaintext_secret():
    raw = open("config/agents.json", encoding="utf-8").read()
    registry = AgentRegistry.from_file("config/agents.json")
    for agent_id in registry.agent_ids():
        assert secret_of(agent_id) not in raw
        assert hash_credential(secret_of(agent_id)) == registry.get(agent_id).credential_sha256


def test_session_ids_are_unique_and_identify_the_agent(sessions):
    opened = [sessions.open_session("bon-agent", secret_of("bon-agent"))[0] for _ in range(50)]
    assert len({s.session_id for s in opened}) == 50
    session, token = sessions.open_session("abus-outils-agent", secret_of("abus-outils-agent"))
    verified = sessions.verify(token)
    assert (verified.agent_id, verified.agent_role, verified.session_id) == (
        "abus-outils-agent", "facturation", session.session_id)


@pytest.mark.parametrize("agent_id,secret", [
    ("bon-agent", "mauvais"), ("inconnu", "x"), ("bon-agent", None), (None, "x")])
def test_authentication_rejects_bad_credentials(sessions, agent_id, secret):
    with pytest.raises(IdentityError) as exc:
        sessions.open_session(agent_id, secret)
    assert exc.value.reason == "authentification_refusee"


def test_tampered_token_rejected(sessions):
    _, token = sessions.open_session("bon-agent", secret_of("bon-agent"))
    payload, sig = token.split(".")
    for bad in (payload + "." + sig[::-1], payload[:-2] + "AA." + sig, "n.importe.quoi", "", None):
        with pytest.raises(IdentityError):
            sessions.verify(bad)


def test_token_forged_with_other_key_rejected(registry, clock):
    other = SessionManager(registry, "autre-cle", clock=clock)
    _, forged = other.open_session("bon-agent", secret_of("bon-agent"))
    mine = SessionManager(registry, "cle-de-test", clock=clock)
    with pytest.raises(IdentityError) as exc:
        mine.verify(forged)
    assert exc.value.reason == "signature_invalide"


def test_session_expires_and_can_be_revoked(sessions, clock):
    session, token = sessions.open_session("bon-agent", secret_of("bon-agent"))
    sessions.verify(token)
    assert sessions.revoke(session.session_id)
    with pytest.raises(IdentityError) as exc:
        sessions.verify(token)
    assert exc.value.reason == "session_inconnue"
    _, token2 = sessions.open_session("bon-agent", secret_of("bon-agent"))
    clock.advance(61)
    with pytest.raises(IdentityError) as exc:
        sessions.verify(token2)
    assert exc.value.reason == "session_expiree"


def test_role_comes_from_registry_not_from_declaration(sessions):
    """Un agent crédit qui se déclare 'rh' reste crédit et l'incohérence est signalée."""
    _, token = sessions.open_session("usurpation-role-agent", secret_of("usurpation-role-agent"))
    ctx, _ = IdentityService(sessions).resolve(token, declared_role="rh")
    assert ctx.verified and ctx.agent_role == "credit"
    assert "role_mismatch" in ctx.flags


def test_claimed_agent_or_session_mismatch_flagged(sessions):
    session, token = sessions.open_session("bon-agent", secret_of("bon-agent"))
    ctx, _ = IdentityService(sessions).resolve(token, claimed_agent_id="exfiltration-agent",
                                               claimed_session_id="autre")
    assert ctx.agent_id == "bon-agent"
    assert {"agent_id_mismatch", "session_id_mismatch"} <= set(ctx.flags)
    ok, _ = IdentityService(sessions).resolve(token, "bon-agent", session.session_id, "credit")
    assert ok.flags == []


def test_missing_token_is_unverified(sessions):
    ctx, session = IdentityService(sessions).resolve(None, claimed_agent_id="bon-agent", declared_role="credit")
    assert not ctx.verified and session is None and "identity_unverified" in ctx.flags
    assert ctx.agent_id == "unknown"


def test_replay_and_trace_correlation_tracked_per_session(sessions):
    session, _ = sessions.open_session("bon-agent", secret_of("bon-agent"))
    assert sessions.note_event(session, "evt-1", "trace-a") is False
    assert sessions.note_event(session, "evt-2", "trace-a") is False
    assert sessions.note_event(session, "evt-1", "trace-b") is True  # rejeu
    assert session.trace_ids == {"trace-a", "trace-b"}


def test_event_attributed_to_verified_agent_and_session_end_to_end(app, clock):
    status, body = app.open_session({"agent_id": "bon-agent", "credential": secret_of("bon-agent")}, {}, "10.0.0.4")
    assert status == 200
    event = {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": "jeu_donnees", "id": "credit"},
             "acteur": {"role": "credit"}, "quantite": 1, "event_id": "evt-1", "parent_event_id": ""}
    _, res = app.handle_event(event, {"X-Session-Token": body["token"]}, "10.0.0.4")
    assert res["agent_id"] == "bon-agent" and res["session_id"] == body["session_id"]
    assert res["decision"] == "autoriser"
    log = [json.loads(l) for l in open(app.log_dir / "evenements.jsonl", encoding="utf-8")]
    assert log[0]["identite"]["agent_id"] == "bon-agent" and log[0]["identite"]["verifie"] is True


def test_multiple_agents_operate_simultaneously_without_identity_mixup(app):
    agents = ["bon-agent", "exfiltration-agent", "abus-outils-agent", "baseline-deviation-agent"]
    roles = {"bon-agent": "credit", "exfiltration-agent": "assistance",
             "abus-outils-agent": "facturation", "baseline-deviation-agent": "credit"}
    resources = {"credit": ("jeu_donnees", "credit"), "assistance": ("jeu_donnees", "clients"),
                 "facturation": ("paiement", "p-1")}
    results, lock = [], threading.Lock()

    def work(agent_id):
        _, s = app.open_session({"agent_id": agent_id, "credential": secret_of(agent_id)}, {}, "10.0.0.9")
        rtype, rid = resources[roles[agent_id]]
        for i in range(25):
            ev = {"type_evenement": "acces_donnees", "action": "lecture", "ressource": {"type": rtype, "id": rid},
                  "acteur": {"role": roles[agent_id]}, "quantite": 1}
            _, res = app.handle_event(ev, {"X-Session-Token": s["token"]}, "10.0.0.9")
            with lock:
                results.append((agent_id, s["session_id"], res["agent_id"], res["session_id"]))

    threads = [threading.Thread(target=work, args=(a,)) for a in agents]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(results) == 100
    assert all(expected == got and sid == gsid for expected, sid, got, gsid in results)
    assert len({sid for _, sid, _, _ in results}) == 4
