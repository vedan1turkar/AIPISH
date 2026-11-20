"""P5c: correlation, campaigns, case membership, search, PDF 7B. Synthetic data, isolated DB."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.correlation.engine as engine_mod
from app.core.db import Base, get_db
from app.core.models import (
    Analysis, AuditEvent, Campaign, CampaignMember, CorrelationState, Entity, Observation, run_additive_migrations,
)
from app.correlation import DISCLAIMER
from app.correlation.config import CorrelationConfig, get_correlation_config
from app.correlation.engine import (
    EntityStat, correlate_analysis, evaluate_pair, rebuild_all, recompute_campaigns, strength,
)
from app.correlation.extract import (
    extract, normalize_display_name, normalize_domain, normalize_public_ip,
)
from app.main import create_app
from tests.authutil import auth_headers, make_user

DEMO = Path(__file__).resolve().parents[1] / "fixtures" / "demo" / "campaign"
FIX = Path(__file__).resolve().parents[1] / "fixtures"
CAMPAIGN_FILES = [f"campaign_member_{i}.eml" for i in range(1, 5)]


# ── fixtures ─────────────────────────────────────────────────────────────
@pytest.fixture
def db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()


@pytest.fixture
def app_db(db):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    return app, db


def _client(app, db, role):
    u, _ = make_user(db, role)
    c = TestClient(app)
    c.headers.update(auth_headers(u))
    return c, u


def _upload(c, path: Path):
    r = c.post("/api/v1/analyses", files={"file": (path.name, path.read_bytes(), "message/rfc822")})
    assert r.status_code == 201, r.text
    return r.json()


def _seed_demo(c) -> dict[str, str]:
    return {p.name: _upload(c, p)["id"] for p in sorted(DEMO.glob("*.eml"))}


_T0 = datetime(2026, 11, 1, tzinfo=timezone.utc)


def _rec(db, n: int, **fields) -> Analysis:
    rec = Analysis(raw_sha256=f"{n:064x}", raw_size_bytes=1, created_at=_T0 + timedelta(minutes=n), **fields)
    db.add(rec)
    db.commit()
    return rec


def _hash(ch: str) -> str:
    return ch * 64


def _stat(etype, value, df, roles_by_analysis):
    st = EntityStat("e-" + value, etype, value, df)
    for a, roles in roles_by_analysis.items():
        st.roles[a] = set(roles)
        st.fields[a] = [(r, f"field.{r}") for r in roles]
    return st


# ── normalisation / extraction ───────────────────────────────────────────
def test_domain_normalisation_idna_case_trailing_dot():
    assert normalize_domain("Mail.Example-Brand.COM.") == "mail.example-brand.com"
    assert normalize_domain("bücher.test") == "xn--bcher-kva.test"
    assert normalize_domain("user@Vendor-Remit-Portal.test") == "vendor-remit-portal.test"
    for bad in ("localhost", "singlelabel", "10.0.0.1", "[1.2.3.4]", "a/b.com", "", None, "-bad-.com"):
        assert normalize_domain(bad) is None


def test_ip_normalisation_public_only():
    assert normalize_public_ip("96.7.128.175") == "96.7.128.175"
    assert normalize_public_ip("::ffff:96.7.128.175") == "96.7.128.175"
    for bad in ("10.0.0.42", "127.0.0.1", "192.168.1.1", "100.64.0.1", "192.0.2.10", "169.254.1.1",
                "::1", "fe80::1", "not-an-ip"):
        assert normalize_public_ip(bad) is None
    assert normalize_display_name("  Accounts-Payable   DESK!! ") == "accounts payable desk"


def test_private_ips_and_trusted_relays_never_become_entities():
    rec = SimpleNamespace(
        forensics_json={
            "relay_chain": [
                {"index": 0, "from_ip": "10.0.0.42", "trusted": False, "from_host": "pc.local"},
                {"index": 1, "from_ip": "96.7.128.175", "trusted": False, "from_host": "relay.attacker-infra.test"},
                {"index": 2, "from_ip": "172.217.14.99", "trusted": False, "from_host": "mx2.amazonses.com"},
                {"index": 3, "from_ip": "2001:4860:4860::8888", "trusted": True, "from_host": "mx.receiver.test"},
            ],
            "candidate_ips": ["10.0.0.42"], "earliest_candidate_ip": "10.0.0.42", "verified_originating_ip": None,
        },
        from_domain="x.test", reply_to_emails=[], return_path=None, message_id=None, urls=[], attachments=[],
        from_display_name=None)
    ips = {(x.value, x.role) for x in extract(rec, get_correlation_config()) if x.type == "public_ip"}
    assert ips == {("96.7.128.175", "relay_ip")}        # private, provider-hosted and trusted hops excluded


# ── link strength rules ──────────────────────────────────────────────────
CFG = CorrelationConfig(stoplist=frozenset({"outlook.com", "gmail.com"}), df_soft=10, df_max=25)


def test_freemail_overlap_never_links():
    s = _stat("sender_domain", "outlook.com", 2, {"a": ["sender_domain"], "b": ["sender_domain"]})
    link = evaluate_pair(CFG, [s], "a", "b")
    assert not link["qualifies"] and link["indicators"] == [] and link["generic_overlaps"]
    assert "stop-listed" in link["generic_overlaps"][0]["generic_reason"]
    assert link["explanation"] == "only generic indicators are shared"


def test_single_weak_indicator_never_links():
    for etype, role in (("message_id_domain", "message_id_domain"), ("sender_domain", "sender_domain"),
                        ("public_ip", "relay_ip"), ("display_name_alias", "display_name")):
        s = _stat(etype, "v-" + etype, 2, {"a": [role], "b": [role]})
        assert not evaluate_pair(CFG, [s], "a", "b")["qualifies"]


def test_two_weak_types_still_do_not_link():
    s1 = _stat("sender_domain", "corp-a.test", 2, {"a": ["sender_domain"], "b": ["sender_domain"]})
    s2 = _stat("public_ip", "96.7.128.175", 2, {"a": ["relay_ip"], "b": ["relay_ip"]})
    link = evaluate_pair(CFG, [s1, s2], "a", "b")
    assert not link["qualifies"] and "weak" in link["explanation"]


def test_one_medium_type_alone_does_not_link():
    s = _stat("reply_to_domain", "drop.test", 2, {"a": ["reply_to_domain"], "b": ["reply_to_domain"]})
    assert not evaluate_pair(CFG, [s], "a", "b")["qualifies"]


def test_strong_indicator_alone_links_with_high_confidence():
    s = _stat("attachment_hash", _hash("a"), 2, {"a": ["attachment_sha256"], "b": ["attachment_sha256"]})
    link = evaluate_pair(CFG, [s], "a", "b")
    assert link["qualifies"] and link["has_strong"] and link["confidence"] == "high"
    assert link["score"] == 0.9


def test_two_independent_types_link_and_same_value_counts_once():
    ip = _stat("public_ip", "96.7.128.175", 2, {"a": ["origin_candidate_ip"], "b": ["origin_candidate_ip"]})
    rt = _stat("reply_to_domain", "drop.test", 2, {"a": ["reply_to_domain"], "b": ["reply_to_domain"]})
    link = evaluate_pair(CFG, [ip, rt], "a", "b")
    assert link["qualifies"] and link["score"] == 0.8 and link["confidence"] == "medium"
    # the same domain seen as sender and message-id domain is ONE indicator, not two types
    snd = _stat("sender_domain", "corp-a.test", 2, {"a": ["sender_domain"], "b": ["sender_domain"]})
    mid = _stat("message_id_domain", "corp-a.test", 2, {"a": ["message_id_domain"], "b": ["message_id_domain"]})
    rt2 = _stat("reply_to_domain", "corp-a.test", 2, {"a": ["reply_to_domain"], "b": ["reply_to_domain"]})
    assert not evaluate_pair(CFG, [snd, mid, rt2], "a", "b")["qualifies"]


def test_conservative_role_origin_vs_relay():
    ip = _stat("public_ip", "96.7.128.175", 2, {"a": ["origin_candidate_ip"], "b": ["relay_ip"]})
    rt = _stat("reply_to_domain", "drop.test", 2, {"a": ["reply_to_domain"], "b": ["reply_to_domain"]})
    link = evaluate_pair(CFG, [ip, rt], "a", "b")
    weights = {i["type"]: i["weight"] for i in link["indicators"]}
    assert weights["public_ip"] == 0.15          # scored as the weaker relay role


def test_document_frequency_damping():
    st = _stat("attachment_hash", _hash("b"), 12, {})
    s = strength(CFG, st, {"attachment_sha256"})
    assert s.damped and s.tier == "medium" and s.weight == 0.45
    st.df = 30
    s = strength(CFG, st, {"attachment_sha256"})
    assert s.weight == 0 and "treated as generic" in s.generic_reason


# ── campaigns through the real pipeline ──────────────────────────────────
def test_demo_campaign_formation_reasons_and_freemail_exclusion(app_db):
    app, db = app_db
    c, _ = _client(app, db, "analyst")
    ids = _seed_demo(c)
    camps = db.query(Campaign).filter_by(status="candidate").all()
    assert len(camps) == 1
    camp = camps[0]
    members = {m.analysis_id for m in db.query(CampaignMember).filter_by(campaign_id=camp.id)}
    assert members == {ids[f] for f in CAMPAIGN_FILES}
    assert ids["freemail_only.eml"] not in members and ids["unrelated.eml"] not in members
    assert camp.label == "Candidate campaign C-0001" and camp.confidence == "medium"
    assert camp.confidence_score == pytest.approx(0.82)
    shared = {(i["type"], i["value"]) for i in camp.reasons["shared_indicators"]}
    assert {("public_ip", "96.7.128.175"), ("reply_to_domain", "vendor-remit-portal.test")} <= shared
    assert not any(v == "outlook.com" for _t, v in shared)
    ev = [e for i in camp.reasons["shared_indicators"] for e in i["evidence"]]
    assert {"forensics.verified_originating_ip", "reply_to[0]"} <= {e["source_field"] for e in ev}
    blob = json.dumps(camp.reasons).lower()
    assert "same attacker" not in blob and "same person" not in blob
    assert camp.reasons["disclaimer"] == DISCLAIMER and "does not identify a human" in DISCLAIMER

    # per-analysis view on the freemail-only email: no link, generic overlap explained
    r = c.get(f"/api/v1/analyses/{ids['freemail_only.eml']}/correlation").json()
    assert r["related"] == [] and r["campaigns"] == []
    assert r["generic_only_overlaps"]["count"] == 4
    assert {g["value"] for g in r["generic_only_overlaps"]["indicators"]} == {"outlook.com"}
    # member view
    r = c.get(f"/api/v1/analyses/{ids['campaign_member_1.eml']}/correlation").json()
    assert r["status"] == "ok" and len(r["related"]) == 3 and all(x["qualifies"] for x in r["related"])
    assert r["campaigns"][0]["id"] == camp.id
    # unrelated
    r = c.get(f"/api/v1/analyses/{ids['unrelated.eml']}/correlation").json()
    assert r["related"] == [] and r["generic_only_overlaps"]["count"] == 0


def test_campaign_detail_graph(app_db):
    app, db = app_db
    c, _ = _client(app, db, "viewer")
    a, _ = _client(app, db, "analyst")
    _seed_demo(a)
    lst = c.get("/api/v1/campaigns").json()
    assert len(lst["items"]) == 1 and lst["items"][0]["member_count"] == 4
    d = c.get(f"/api/v1/campaigns/{lst['items'][0]['id']}").json()
    kinds = {n["kind"] for n in d["graph"]["nodes"]}
    assert {"analysis", "public_ip", "reply_to_domain"} <= kinds
    assert all(e["source"].startswith("a:") and e["target"].startswith("e:") for e in d["graph"]["edges"])
    assert all(e["source_field"] for e in d["graph"]["edges"])
    assert "body_text" not in json.dumps(d)
    assert c.get("/api/v1/campaigns/nope").status_code == 404
    g = c.get("/api/v1/graph/entities/public_ip/96.7.128.175").json()
    assert g["entity"]["df"] == 4 and len(g["analyses"]) == 4
    assert c.get("/api/v1/graph/entities/public_ip/10.0.0.1").status_code == 404


def test_rebuild_is_idempotent_and_deterministic(app_db):
    app, db = app_db
    c, _ = _client(app, db, "analyst")
    _seed_demo(c)
    snap = lambda: (  # noqa: E731
        sorted((x.id, x.label, x.status, x.version, x.fingerprint, x.confidence_score) for x in db.query(Campaign)),
        sorted((m.campaign_id, m.analysis_id) for m in db.query(CampaignMember)),
        db.query(Entity).count(), db.query(Observation).count())
    before = snap()
    r1 = rebuild_all(db)
    after1 = snap()
    r2 = rebuild_all(db)
    after2 = snap()
    assert before == after1 == after2
    assert r1 == r2 and r1["campaigns_unchanged"] == 1 and r1["campaigns_created"] == 0
    keys = [(o.entity_id, o.analysis_id, o.role, o.source_field) for o in db.query(Observation)]
    assert len(keys) == len(set(keys))


def test_campaign_merge_when_new_analysis_bridges_two(db):
    a1 = _rec(db, 1, attachments=[{"sha256": _hash("a")}])
    a2 = _rec(db, 2, attachments=[{"sha256": _hash("a")}])
    a3 = _rec(db, 3, attachments=[{"sha256": _hash("b")}])
    a4 = _rec(db, 4, attachments=[{"sha256": _hash("b")}])
    for r in (a1, a2, a3, a4):
        correlate_analysis(db, r.id)
    db.commit()
    first = {c.number: c for c in db.query(Campaign).filter_by(status="candidate")}
    assert sorted(first) == [1, 2]
    bridge = _rec(db, 5, attachments=[{"sha256": _hash("a")}, {"sha256": _hash("b")}])
    correlate_analysis(db, bridge.id)
    db.commit()
    live = db.query(Campaign).filter_by(status="candidate").all()
    assert len(live) == 1 and live[0].number == 1                  # the older campaign survives
    members = {m.analysis_id for m in db.query(CampaignMember).filter_by(campaign_id=live[0].id)}
    assert members == {a1.id, a2.id, a3.id, a4.id, bridge.id}
    merged = db.get(Campaign, first[2].id)
    assert merged.status == "merged" and merged.merged_into == live[0].id and merged.version == 2


def test_campaign_dissolves_when_indicator_becomes_generic(db, monkeypatch):
    for n in (1, 2):
        correlate_analysis(db, _rec(db, n, attachments=[{"sha256": _hash("c")}]).id)
    db.commit()
    camp = db.query(Campaign).one()
    assert camp.status == "candidate"
    recompute_campaigns(db, CorrelationConfig(stoplist=frozenset(), df_soft=1, df_max=1))
    db.commit()
    assert db.get(Campaign, camp.id).status == "dissolved"


def test_correlation_failure_is_isolated(app_db, monkeypatch):
    app, db = app_db
    c, _ = _client(app, db, "analyst")
    normal = _upload(c, FIX / "eml" / "multihop_auth.eml")

    def boom(*a, **k):
        raise RuntimeError("synthetic correlation failure with secret-looking text")

    monkeypatch.setattr(engine_mod, "record_observations", boom)
    broken = _upload(c, FIX / "eml" / "multihop_auth.eml")
    strip = lambda d: {k: v for k, v in d.items() if k not in ("id", "created_at")}  # noqa: E731
    assert strip(normal) == strip(broken)
    st = db.get(CorrelationState, broken["id"])
    assert st.status == "error" and st.error_type == "RuntimeError"
    assert db.get(Analysis, broken["id"]) is not None
    assert c.get(f"/api/v1/analyses/{broken['id']}/correlation").json()["status"] == "error"


def test_rules_unchanged_by_correlation(app_db):
    app, db = app_db
    c, _ = _client(app, db, "analyst")
    r = _upload(c, FIX / "demo" / "bec_wire_change.eml")
    assert r["detection"]["score"] == 100 and r["detection"]["verdict"] == "phishing_fraud_likely"


# ── cases ────────────────────────────────────────────────────────────────
def test_case_add_remove_duplicate_validation_and_audit(app_db):
    app, db = app_db
    c, analyst = _client(app, db, "analyst")
    v, _ = _client(app, db, "viewer")
    ids = _seed_demo(c)
    case = c.post(f"/api/v1/investigations/from-analysis/{ids['campaign_member_1.eml']}").json()
    cid = case["id"]
    r = c.post(f"/api/v1/investigations/{cid}/analyses", json={"analysis_id": ids["campaign_member_2.eml"]})
    assert r.status_code == 201 and len(r.json()["analyses"]) == 2
    dup = c.post(f"/api/v1/investigations/{cid}/analyses", json={"analysis_id": ids["campaign_member_2.eml"]})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "ALREADY_MEMBER"
    assert c.post(f"/api/v1/investigations/{cid}/analyses", json={"analysis_id": "nope"}).status_code == 404
    assert c.post("/api/v1/investigations/nocase/analyses", json={"analysis_id": ids["unrelated.eml"]}).status_code == 404
    assert v.post(f"/api/v1/investigations/{cid}/analyses", json={"analysis_id": ids["unrelated.eml"]}).status_code == 403
    listing = v.get(f"/api/v1/investigations/{cid}/analyses").json()
    assert [x["analysis"]["id"] for x in listing] == [ids["campaign_member_1.eml"], ids["campaign_member_2.eml"]]
    assert listing[0]["campaigns"] and "body_text" not in json.dumps(listing)
    ind = v.get(f"/api/v1/investigations/{cid}/indicators").json()["indicators"]
    top = {(i["type"], i["value"]): i for i in ind}
    assert top[("public_ip", "96.7.128.175")]["case_count"] == 2
    assert top[("sender_domain", "outlook.com")]["generic_reason"]
    assert v.delete(f"/api/v1/investigations/{cid}/analyses/{ids['campaign_member_2.eml']}").status_code == 403
    r = c.delete(f"/api/v1/investigations/{cid}/analyses/{ids['campaign_member_2.eml']}")
    assert r.status_code == 200 and len(r.json()["analyses"]) == 1
    assert c.delete(f"/api/v1/investigations/{cid}/analyses/{ids['campaign_member_2.eml']}").status_code == 404
    events = {(e.event_type, e.actor_user_id) for e in db.query(AuditEvent).filter(AuditEvent.case_id == cid)}
    assert ("case_analysis_added", analyst.id) in events and ("case_analysis_removed", analyst.id) in events


# ── search ───────────────────────────────────────────────────────────────
def test_search_filters_pagination_injection_and_no_bodies(app_db):
    app, db = app_db
    a, _ = _client(app, db, "analyst")
    v, _ = _client(app, db, "viewer")
    ids = _seed_demo(a)
    case = a.post(f"/api/v1/investigations/from-analysis/{ids['unrelated.eml']}").json()
    s = lambda **p: v.get("/api/v1/search", params=p)  # noqa: E731

    r = s(q="vendor-remit-portal", type="analysis").json()["results"]["analysis"]
    assert r["total"] == 4
    assert s(q="96.7.128.175", type="entity").json()["results"]["entity"]["items"][0]["analyses"] == 4
    assert s(q=ids["unrelated.eml"][:10], type="analysis").json()["results"]["analysis"]["total"] == 1
    sha = db.get(Analysis, ids["freemail_only.eml"]).raw_sha256
    assert s(q=sha[:16], type="analysis").json()["results"]["analysis"]["items"][0]["id"] == ids["freemail_only.eml"]
    assert s(q=case["case_number"], type="case").json()["results"]["case"]["total"] == 1
    assert s(q="C-0001", type="campaign").json()["results"]["campaign"]["total"] == 1
    assert s(q="outlook.com", type="entity", entity_type="sender_domain").json()["results"]["entity"]["total"] == 1
    page1 = s(q="synthetic", type="analysis", limit=2).json()["results"]["analysis"]
    page2 = s(q="synthetic", type="analysis", limit=2, offset=2).json()["results"]["analysis"]
    assert page1["total"] == 6 and len(page1["items"]) == 2
    assert not {i["id"] for i in page1["items"]} & {i["id"] for i in page2["items"]}
    verdicts = s(type="analysis", verdict="clean").json()["results"]["analysis"]
    assert all(i["detection_verdict"] == "clean" for i in verdicts["items"])
    assert s(type="analysis", date_from="2099-01-01").json()["results"]["analysis"]["total"] == 0
    assert s(limit=500).status_code == 400 and s(q="x" * 201).status_code == 400
    # injection attempts are just text
    for evil in ("' OR 1=1 --", "%", "\\", "'; DROP TABLE analysis; --", "\" OR \"\"=\""):
        r = s(q=evil)
        assert r.status_code == 200
        totals = {k: v["total"] for k, v in r.json()["results"].items()}
        assert set(totals.values()) == {0}, (evil, totals)
    # "_" is a literal underscore, not a LIKE wildcard: it matches only the 4 analyses whose verdict
    # (phishing_fraud_likely) really contains one, not all 6
    literal = s(q="_", type="analysis").json()["results"]["analysis"]
    assert literal["total"] == sum("_" in (x.detection_verdict or "") for x in db.query(Analysis)) < 6
    assert db.query(Analysis).count() == 6
    blob = s(q="synthetic").text
    assert "banking details changed" not in blob and "body_text" not in blob


# ── permissions ──────────────────────────────────────────────────────────
NEW_READ = ["/api/v1/campaigns", "/api/v1/search?q=x", "/api/v1/analyses/x/correlation",
            "/api/v1/graph/entities/public_ip/96.7.128.175", "/api/v1/investigations/x/analyses",
            "/api/v1/investigations/x/indicators", "/api/v1/campaigns/x"]


def test_new_routes_permissions(app_db):
    app, db = app_db
    anon = TestClient(app)
    for p in NEW_READ:
        assert anon.get(p).status_code == 401
    assert anon.post("/api/v1/correlation/rebuild").status_code == 401
    assert anon.delete("/api/v1/investigations/x/analyses/y").status_code == 401
    v, _ = _client(app, db, "viewer")
    for p in NEW_READ:
        assert v.get(p).status_code not in (401, 403), p
    assert v.post("/api/v1/correlation/rebuild").status_code == 403
    a, _ = _client(app, db, "analyst")
    assert a.post("/api/v1/correlation/rebuild").status_code == 403
    adm, admin = _client(app, db, "admin")
    r = adm.post("/api/v1/correlation/rebuild")
    assert r.status_code == 200 and r.json()["analyses"] == 0
    ev = db.query(AuditEvent).filter_by(event_type="correlation_rebuilt").one()
    assert ev.actor_user_id == admin.id


# ── PDF 7B ───────────────────────────────────────────────────────────────
@pytest.fixture
def nocompress(monkeypatch):
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def _pdf_text(pdf: bytes) -> str:
    out = []
    for block in re.findall(rb"\bBT\b(.*?)\bET\b", pdf, re.S):
        for line in re.split(rb"T\*", block):
            parts = re.findall(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", line)
            if parts:
                text = b"".join(parts).decode("latin-1").replace("\\(", "(").replace("\\)", ")").strip()
                out.append(re.sub(r"([_.-]) ", r"\1", text))
    return " ".join(out)


def _build(corr):
    from app.reports.pdf import build_report_pdf
    return build_report_pdf(case_dict={"case_number": "CASE-T"}, analysis_row={"id": "a", "sha256": "f" * 64},
                            detection={}, forensics={}, auth={}, enrichment={}, integrity={"result": "unavailable"},
                            report_id="RPT-T", correlation=corr)


def test_pdf_section_empty_and_escaping(nocompress):
    empty = {"status": "ok", "related": [], "campaigns": [], "generic_only_overlaps": {"count": 0},
             "rule": "RULE", "disclaimer": DISCLAIMER, "snapshot_at": "2026-11-20T10:00:00+00:00"}
    txt = _pdf_text(_build(empty))
    assert "Related Analyses / Candidate Campaigns" in txt
    assert "No related analyses recorded at report time" in txt and "does not identify a human" in txt
    evil = {**empty, "campaigns": [{"label": "<b>C-9</b>", "confidence": "medium", "confidence_score": 0.8,
                                    "member_count": 4, "id": "cid", "version": 3}],
            "related": [{"analysis": {"id": "abcdef0123", "created_at": None}, "qualifies": True, "score": 0.8,
                         "indicators": [{"type": "reply_to_domain", "value": "<script>x</script>", "tier": "medium"}]}]}
    txt = _pdf_text(_build(evil))
    assert "<b>C-9</b>" in txt and "<script>x</script>" in txt      # printed literally, not interpreted
    assert "version 3" in txt


def test_pdf_report_includes_campaign_and_records_version(app_db, nocompress):
    app, db = app_db
    c, _ = _client(app, db, "analyst")
    ids = _seed_demo(c)
    aid = ids["campaign_member_1.eml"]
    case = c.post(f"/api/v1/investigations/from-analysis/{aid}").json()
    pdf = c.get(f"/api/v1/investigations/{case['id']}/report/{aid}")
    assert pdf.status_code == 200
    txt = _pdf_text(pdf.content)
    assert "Candidate campaign C-0001" in txt and "96.7.128.175" in txt
    ev = db.query(AuditEvent).filter_by(event_type="report_generated").one()
    camp = db.query(Campaign).one()
    assert ev.detail["campaigns"] == [{"id": camp.id, "version": camp.version}]


def test_additive_migrations_idempotent_on_file_db(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'm.sqlite'}")
    run_additive_migrations(eng)
    run_additive_migrations(eng)
    from sqlalchemy import inspect
    names = set(inspect(eng).get_table_names())
    assert {"corr_entity", "corr_observation", "corr_campaign", "corr_campaign_member", "corr_state"} <= names
    idx = {i["name"] for i in inspect(eng).get_indexes("analysis")}
    assert {"ix_analysis_from_domain", "ix_analysis_detection_verdict", "ix_analysis_created_at"} <= idx


def test_seed_demo_campaign_cli_refuses_outside_dev(capsys):
    from app import cli
    assert cli.main(["seed-demo-campaign"]) == 2


def test_identical_resubmissions_never_link_or_inflate_frequency(app_db):
    app, db = app_db
    c, _ = _client(app, db, "analyst")
    path = DEMO / "campaign_member_1.eml"
    first = _upload(c, path)["id"]
    for _ in range(3):
        _upload(c, path)                       # the same .eml again: duplicates, not new evidence
    assert db.query(Campaign).count() == 0
    r = c.get(f"/api/v1/analyses/{first}/correlation").json()
    assert r["related"] == [] and r["duplicate_submissions_total"] == 3
    ip = next(e for e in r["entities"] if e["type"] == "public_ip")
    assert ip["df"] == 1                        # one distinct message
    _upload(c, DEMO / "campaign_member_2.eml")  # a different message sharing infra → links
    assert db.query(Campaign).filter_by(status="candidate").count() == 1
