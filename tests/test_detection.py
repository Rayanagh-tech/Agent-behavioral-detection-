import pytest

from secres.config import with_overrides
from secres.detection import BehavioralDetectionEngine


def types(findings):
    return [f.detection_type for f in findings]


def feed(engine, make_event, count, step=1.0, start=1_000_000.0, **kw):
    out = []
    for i in range(count):
        out.extend(engine.process(make_event(at=start + i * step, **kw)))
    return out


# ---------------------------------------------------------------- Niveau 1
def test_unauthorized_resource_access(engine, make_event):
    f = engine.process(make_event(agent_id="c1", role="credit", rid="rh", qty=1))
    assert types(f) == ["unauthorized_resource_access"] and f[0].severity == "high"
    assert f[0].legacy_code == "acces_non_autorise"
    assert f[0].agent_id == "c1" and f[0].session_id == "s-1" and f[0].trace_id == "t" * 32


def test_unauthorized_tool_usage(engine, make_event):
    f = engine.process(make_event(role="credit", etype="appel_outil", action="appel", rtype="outil", rid="api_paiement"))
    assert types(f) == ["unauthorized_tool_usage"]


def test_authorized_access_has_no_finding(engine, make_event):
    assert engine.process(make_event(role="credit", rid="credit", qty=2)) == []


def test_invalid_operations(engine, make_event):
    assert "invalid_operation" in types(engine.process(make_event(etype="teleportation")))
    assert "invalid_operation" in types(engine.process(make_event(action="supprimer_tout")))
    assert "invalid_operation" in types(engine.process(make_event(flags=["negative_quantity"])))


def test_approval_bypass_and_sensitive_without_metadata(engine, make_event):
    bypass = engine.process(make_event(role="facturation", etype="operation", action="rembourser", rtype="paiement",
                                       rid="p-1", approval=(True, False)))
    assert types(bypass) == ["approval_bypass"] and bypass[0].legacy_code == "approbation_requise_absente_ou_contournee"
    sneaky = engine.process(make_event(role="facturation", etype="operation", action="rembourser", rtype="paiement",
                                       rid="p-2", approval=(None, None)))
    assert types(sneaky) == ["suspicious_action"]
    ok = engine.process(make_event(role="credit", etype="operation", action="accorder_credit", rtype="compte_credit",
                                   rid="c-1", approval=(True, True)))
    assert ok == []


def test_single_event_exfiltration_and_tool_abuse_thresholds(engine, make_event):
    assert types(engine.process(make_event(qty=120, bytes_=48000))) == ["data_exfiltration_suspected"]
    f = engine.process(make_event(agent_id="b", role="facturation", etype="appel_outil", action="appel",
                                  rtype="outil", rid="api_paiement", qty=9))
    assert types(f) == ["tool_abuse_frequency"]


def test_repeated_sensitive_operations(engine, make_event):
    kw = dict(role="facturation", etype="operation", action="rembourser", rtype="paiement", rid="p-1", approval=(True, True))
    f = feed(engine, make_event, 3, step=5, **kw)
    assert types(f) == ["repeated_sensitive_operations"]
    assert f[0].evidence["count"] == 3


def test_identity_flags_become_findings(engine, make_event):
    f = engine.process(make_event(flags=["role_mismatch"]))
    assert types(f) == ["identity_spoofing"] and f[0].severity == "critical"
    f = engine.process(make_event(agent_id="unknown", role="unknown", session="unauthenticated", verified=False,
                                  flags=["identity_unverified"]))
    assert types(f) == ["identity_unverified"]


# ---------------------------------------------------------------- Niveau 2
def test_excessive_data_reads(engine, make_event):
    f = feed(engine, make_event, 45, step=0.5, role="credit", rid="credit", qty=1)
    assert "excessive_data_reads" in types(f)
    finding = next(x for x in f if x.detection_type == "excessive_data_reads")
    assert finding.level == 2 and finding.evidence["reads"] >= 40


def test_repeated_tool_calls_payment_api(engine, make_event):
    f = feed(engine, make_event, 12, step=2, agent_id="b", role="facturation", etype="appel_outil", action="appel",
             rtype="outil", rid="api_paiement", qty=1)
    assert "repeated_payment_api_calls" in types(f)
    assert f[0].evidence["tool"] == "api_paiement"


def test_abnormal_tool_frequency(engine, make_event, det_config, acl):
    engine = BehavioralDetectionEngine(with_overrides(det_config, time_window={"tool_frequency": {"max_calls_per_tool": 6},
                                                                              "payment_api_calls": {"max_calls": 999}}), acl)
    f = feed(engine, make_event, 8, step=1, agent_id="b", role="facturation", etype="appel_outil", action="appel",
             rtype="outil", rid="api_paiement", qty=1)
    assert types(f) == ["abnormal_tool_frequency"]


def test_customer_record_volume(engine, make_event):
    f = feed(engine, make_event, 5, step=10, qty=45)  # 5 x 45 = 225 fiches (chaque lecture < seuil unitaire)
    assert "customer_record_volume" in types(f)
    single = BehavioralDetectionEngine(engine.config, engine.rules.acl)
    assert "customer_record_volume" not in types(single.process(make_event(agent_id="z", qty=49)))


def test_suspicious_sequence(engine, make_event):
    engine.process(make_event(at=1_000_000, qty=5))
    engine.process(make_event(at=1_000_001, qty=5))
    f = engine.process(make_event(at=1_000_002, etype="operation", action="exporter", rtype="document", rid="rapport"))
    assert types(f) == ["suspicious_sequence"]
    assert len(f[0].evidence["event_ids"]) == 2  # pas 1 (première lecture) + pas 2 (export)


def test_sequence_not_flagged_when_out_of_order_or_too_slow(engine, make_event):
    f = engine.process(make_event(at=1_000_000, etype="operation", action="exporter", rtype="document", rid="r"))
    f += engine.process(make_event(at=1_000_001, qty=5))
    assert f == []
    e2 = BehavioralDetectionEngine(engine.config, engine.rules.acl)
    e2.process(make_event(agent_id="z", at=1_000_000, qty=5))
    late = e2.process(make_event(agent_id="z", at=1_000_500, etype="operation", action="exporter", rtype="document", rid="r"))
    assert late == []


def test_gradual_data_exfiltration_through_small_requests(engine, make_event):
    f = feed(engine, make_event, 8, step=0.3, qty=18)  # chaque lecture < seuil V0, cumul 144
    assert types(f) == ["gradual_exfiltration"]
    assert f[0].evidence["cumulative_records"] >= 100 and f[0].severity == "high"
    assert all(x.detection_type != "data_exfiltration_suspected" for x in f)


def test_thresholds_come_from_configuration(det_config, acl, make_event):
    strict = with_overrides(det_config, time_window={"gradual_exfiltration": {"cumulative_records": 40, "min_requests": 3}})
    assert "gradual_exfiltration" in types(feed(BehavioralDetectionEngine(strict, acl), make_event, 4, step=1, qty=15))
    lax = with_overrides(det_config, time_window={"gradual_exfiltration": {"cumulative_records": 10_000}})
    assert feed(BehavioralDetectionEngine(lax, acl), make_event, 8, step=1, qty=18) == []


def test_window_expiry_resets_counts(engine, make_event):
    assert "gradual_exfiltration" not in types(feed(engine, make_event, 8, step=100, qty=18))  # trop espacé (>300 s)


def test_cooldown_limits_alert_flood(engine, make_event):
    f = feed(engine, make_event, 20, step=0.5, qty=18)
    assert types(f).count("gradual_exfiltration") == 1


# ---------------------------------------------------------------- Niveau 3
def learn(engine, make_event, n=25, agent="base", **kw):
    for i in range(n):
        out = engine.process(make_event(agent_id=agent, role="credit", rid="credit", qty=1 + i % 3,
                                        at=1_000_000 + i * 2, **kw))
        assert out == [], out


def test_baseline_established_then_quantity_deviation(engine, make_event):
    learn(engine, make_event)
    profile = engine.get_profile("base")
    assert profile["established"] and "jeu_donnees/credit" in profile["resources"]
    f = engine.process(make_event(agent_id="base", role="credit", rid="credit", qty=40, at=1_000_100))
    assert types(f) == ["baseline_deviation"] and f[0].level == 3
    kinds = [d["kind"] for d in f[0].evidence["deviations"]]
    assert kinds == ["quantity_outlier"]
    assert f[0].evidence["deviations"][0]["z_score"] >= 3


def test_baseline_new_resource_and_new_tool(engine, make_event):
    learn(engine, make_event)
    f = engine.process(make_event(agent_id="base", role="credit", etype="operation", action="accorder_credit",
                                  rtype="compte_credit", rid="c-9", approval=(True, True), at=1_000_100))
    assert types(f) == ["baseline_deviation"]
    assert f[0].evidence["deviations"][0]["kind"] == "new_resource"


def test_baseline_not_established_before_min_events_no_alert(engine, make_event):
    for i in range(10):
        assert engine.process(make_event(agent_id="young", role="credit", rid="credit", qty=1, at=1_000_000 + i)) == []
    assert engine.process(make_event(agent_id="young", role="credit", rid="credit", qty=40, at=1_000_100)) == []
    assert engine.get_profile("young")["established"] is False


def test_baseline_rate_spike(engine, make_event):
    learn(engine, make_event)
    f = []
    for i in range(30):  # rafale : 30 événements en 3 s alors que l'agent en faisait 1 toutes les 2 s
        f += engine.process(make_event(agent_id="base", role="credit", rid="credit", qty=2, at=1_000_100 + i * 0.1))
    assert any(d["kind"] == "rate_spike" for x in f for d in x.evidence["deviations"])


def test_anomalous_events_do_not_poison_baseline(engine, make_event):
    learn(engine, make_event)
    before = engine.get_profile("base")["events_observed"]
    engine.process(make_event(agent_id="base", role="credit", rid="credit", qty=40, at=1_000_100))
    assert engine.get_profile("base")["events_observed"] == before


def test_baselines_are_per_agent(engine, make_event):
    learn(engine, make_event, agent="base")
    assert engine.get_profile("autre") is None
    assert engine.process(make_event(agent_id="autre", role="credit", rid="credit", qty=40, at=1_000_100)) == []


def test_normal_behavior_produces_no_false_alerts(engine, make_event):
    """Une heure de trafic normal (3 agents, 1 opération toutes les 30 s, volumes faibles) : aucun constat."""
    plans = [("a-credit", "credit", "jeu_donnees", "credit"), ("a-support", "assistance", "jeu_donnees", "clients"),
             ("a-pay", "facturation", "paiement", "p-1")]
    findings = []
    for i in range(120):
        for agent, role, rtype, rid in plans:
            findings += engine.process(make_event(agent_id=agent, role=role, rtype=rtype, rid=rid,
                                                  qty=1 + (i % 4), at=1_000_000 + i * 30))
    assert findings == []


def test_finding_structure_is_complete(engine, make_event):
    f = engine.process(make_event(role="credit", rid="rh"))[0].to_dict()
    for key in ("finding_id", "agent_id", "session_id", "trace_id", "detection_type", "severity",
                "description", "evidence", "timestamp", "recommended_action"):
        assert f[key] not in (None, ""), key
    assert engine.store.get(f["finding_id"]).to_dict() == f
    assert engine.store.query(agent_id="agent-a")[0].finding_id == f["finding_id"]


def test_sustained_fast_customer_reads_are_flagged_by_design(engine, make_event):
    """Contre-exemple documenté : lire des fiches clients toutes les 3 s pendant plusieurs minutes est suspect."""
    f = feed(engine, make_event, 120, step=3, qty=2)
    assert "gradual_exfiltration" in types(f)
