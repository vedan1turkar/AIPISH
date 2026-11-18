"""R5 labelled dataset: labels, dedup, leakage-safe splits, synthetic separation,
committed manifest/data-card consistency and reproducibility (all offline)."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import random
from collections import Counter, defaultdict
from email.message import EmailMessage
from pathlib import Path

import pytest

from app.ml.dataset import build, synthetic
from app.ml.dataset.dedup import hamming, simhash
from app.ml.dataset.labels import LABEL_MAP, LABELS, map_label
from app.ml.dataset.normalize import Excluded, RawMessage, normalize
from app.ml.dataset.split import SPLITS, leakage_report

DATA = Path(__file__).resolve().parents[3] / "data"
MAX_SYNTHETIC_FRACTION = 0.15


def _eml(frm, subject, body, msgid=None, reply_to=None, html=False, to="victim@corp.test"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, to, subject
    m["Date"] = "Tue, 05 Mar 2002 10:00:00 +0000"
    if msgid:
        m["Message-ID"] = f"<{msgid}>"
    if reply_to:
        m["In-Reply-To"] = f"<{reply_to}>"
    m.set_content(body, subtype="html" if html else "plain")
    return bytes(m)


def _rm(source, label, member, raw):
    return RawMessage(source, f"{source}.fixture", member, label, raw)


LOREM = ("The quarterly logistics review covers warehouse throughput, carrier performance, "
         "inventory accuracy and the plan for the regional distribution centre next spring.")


def _fixture_messages() -> list[RawMessage]:
    msgs = [
        # thread of two legit messages
        _rm("spamassassin", "easy_ham", "a/1", _eml("Ann <ann@lists.alpha.test>", "Build server notes",
                                                    LOREM, msgid="t1@alpha.test")),
        _rm("spamassassin", "easy_ham", "a/2", _eml("Bob <bob@beta.test>", "Re: Build server notes",
                                                    "Agreed, the compiler flags matter. " * 4,
                                                    msgid="t2@beta.test", reply_to="t1@alpha.test")),
        # exact duplicate of a/1 content under another file name
        _rm("spamassassin", "easy_ham_2", "b/1", _eml("Ann <ann@lists.alpha.test>", "Build server notes",
                                                      LOREM, msgid="t1-copy@alpha.test")),
        # near-duplicate phishing pair (one word changed), different senders
        _rm("nazario", "phishing", "p#0", _eml("Bank <alert@bank-one.test>", "Verify your account now",
                                               "Dear customer your account is suspended please verify at "
                                               "http://bank-one.test.login.example/verify within 24 hours "
                                               "or it will be closed permanently by our security team today.")),
        _rm("nazario", "phishing", "p#1", _eml("Bank <notice@bank-two.test>", "Confirm your details",
                                               "Dear member your account is suspended please verify at "
                                               "http://bank-one.test.login.example/verify within 24 hours "
                                               "or it will be closed permanently by our security team today.")),
        _rm("nazario", "phishing", "p#2", _eml("Shop <x@shop-three.test>", "Your order has shipped",
                                               "<p>Track your parcel <a href='http://track.example/abc'>here"
                                               "</a> and contact support@shop-three.test.</p>", html=True)),
        # tiny body -> excluded
        _rm("spamassassin", "hard_ham", "c/1", _eml("C <c@gamma.test>", "x", "ok")),
    ]
    for i in range(12):
        msgs.append(_rm("enron", "sent_mail", f"maildir/u{i}/sent/{i}.",
                        _eml(f"U{i} <u{i}@enron.test>", f"Topic number {i} for review",
                             f"Message {i}: " + " ".join(random.Random(i).choice(LOREM.split())
                                                         for _ in range(40)))))
    return msgs + synthetic.generate(per_template=4)


@pytest.fixture(scope="module")
def built():
    return build.prepare(_fixture_messages())


# ── labels ────────────────────────────────────────────────────────────────

def test_taxonomy_and_every_mapping_target_is_valid():
    assert LABELS == ("legitimate", "suspicious", "impersonated", "phishing", "fraud")
    assert {t for t, _ in LABEL_MAP.values()} <= set(LABELS)
    assert all(reason.strip() for _, reason in LABEL_MAP.values())


def test_unmapped_label_is_rejected():
    with pytest.raises(KeyError):
        map_label("spamassassin", "spam")
    with pytest.raises(KeyError):
        map_label("nazario", "legitimate")


def test_every_synthetic_family_is_mapped():
    for tpl in synthetic.TEMPLATES:
        assert map_label("synthetic", tpl["family"]) in {"fraud", "impersonated"}


def test_built_labels_follow_mapping(built):
    records, _ = built
    for r in records:
        assert r["label"] == LABEL_MAP[(r["source"], r["original_label"])][0]


# ── normalisation ─────────────────────────────────────────────────────────

def test_normalize_masks_addresses_urls_and_drops_recipient():
    rec = normalize(_rm("nazario", "phishing", "x", _eml(
        "A <a@b.test>", "Mail me at evil@c.test", "Go to http://evil.test/x or write to ops@evil.test now "
        "please, this is long enough.", to="secret.person@victim.test")))
    assert "evil@c.test" not in rec["subject"] and "<EMAIL>" in rec["subject"]
    assert "http://" not in rec["body"] and "<URL>" in rec["body"]
    assert rec["url_hosts"] == ["evil.test"]
    assert "secret.person" not in json.dumps(rec)


def test_html_body_is_converted_and_hrefs_kept(built):
    records, _ = built
    rec = next(r for r in records if r["source_member"] == "p#2")
    assert "<p>" not in rec["body"] and rec["has_html"]
    assert "track.example" in rec["url_hosts"]


def test_tiny_body_is_excluded_with_reason(built):
    _, excluded = built
    assert any(e["source_member"] == "c/1" and e["reason"] == "empty_or_tiny_body" for e in excluded)
    with pytest.raises(Excluded):
        normalize(_rm("spamassassin", "easy_ham", "z", _eml("a@b.test", "s", "hi")))


# ── duplicates ────────────────────────────────────────────────────────────

def test_exact_duplicate_removed_and_logged(built):
    records, excluded = built
    members = {r["source_member"] for r in records}
    assert "a/1" not in members or "b/1" not in members
    dup = [e for e in excluded if e["reason"] == "exact_duplicate"]
    assert any(e["source_member"] in {"a/1", "b/1"} for e in dup)
    assert len({r["norm_sha256"] for r in records}) == len(records)


def test_exact_duplicate_with_conflicting_labels_drops_all_copies():
    raw = _eml("x@y.test", "Same text", LOREM)
    recs, exc = build.prepare([_rm("nazario", "phishing", "1", raw),
                               _rm("spamassassin", "easy_ham", "1", _eml("x@y.test", "Same text", LOREM,
                                                                         msgid="other@y.test"))])
    assert recs == []
    assert {e["reason"] for e in exc} == {"exact_duplicate_label_conflict"}


def test_near_duplicates_are_clustered(built):
    records, _ = built
    by = {r["source_member"]: r for r in records}
    assert by["p#0"]["near_dup_cluster"] == by["p#1"]["near_dup_cluster"]
    assert by["p#0"]["near_dup_cluster"] != by["p#2"]["near_dup_cluster"]


def test_simhash_distance_behaviour():
    a = simhash(LOREM)
    assert hamming(a, simhash(LOREM.replace("spring", "summer"))) <= 12
    assert hamming(a, simhash("completely different words about gardening and tomatoes")) > 12


# ── splits / leakage ──────────────────────────────────────────────────────

def test_no_key_spans_two_splits(built):
    records, _ = built
    assert set(leakage_report(records).values()) == {0}
    assert {r["split"] for r in records} <= set(SPLITS)


def test_related_messages_share_a_split(built):
    records, _ = built
    by = {r["source_member"]: r for r in records}
    thread_root = by.get("a/1") or by["b/1"]
    assert by["a/2"]["group_id"] == thread_root["group_id"]          # thread
    assert by["p#0"]["split"] == by["p#1"]["split"]                  # near-dup campaign
    per_tpl = defaultdict(set)
    for r in records:
        if r["synthetic_template"]:
            per_tpl[r["synthetic_template"]].add(r["split"])
    assert per_tpl and all(len(s) == 1 for s in per_tpl.values())  # template


# ── synthetic vs real ─────────────────────────────────────────────────────

def test_synthetic_is_flagged_and_distinguishable(built):
    records, _ = built
    for r in records:
        assert r["is_synthetic"] == (r["source"] == "synthetic")
        assert bool(r["synthetic_template"]) == r["is_synthetic"]
        if r["is_synthetic"]:
            assert r["from_domain"].endswith((".test", ".example"))
            assert r["message_id"].endswith("@synthetic.aipish.test")
        # the marker header is metadata only; it never leaks into model text
        assert "AIPISH" not in r["body"] and "aipish" not in r["subject"].lower()


def test_synthetic_raw_carries_marker_header():
    for rm in synthetic.generate(per_template=1):
        assert b"X-AIPISH-Synthetic: true" in rm.raw
        assert rm.source == "synthetic" and rm.synthetic_template


def test_synthetic_generation_is_deterministic():
    a = [m.raw for m in synthetic.generate(per_template=3)]
    assert a == [m.raw for m in synthetic.generate(per_template=3)]
    assert a != [m.raw for m in synthetic.generate(seed=1, per_template=3)]


# ── reproducibility ───────────────────────────────────────────────────────

def test_prepare_is_order_independent_and_reproducible():
    msgs = _fixture_messages()
    shuffled = msgs[:]
    random.Random(7).shuffle(shuffled)
    a = build._csv(build.prepare(msgs)[0], build.MANIFEST_FIELDS)
    b = build._csv(build.prepare(shuffled)[0], build.MANIFEST_FIELDS)
    assert a == b


def test_write_outputs_round_trip(tmp_path):
    records, excluded = build.prepare(_fixture_messages())
    (tmp_path / "DATA_CARD.md").write_text(f"# card\n{build.BEGIN}\n{build.END}\ntail\n")
    stats = build.write_outputs(records, excluded, tmp_path)
    manifest = (tmp_path / "manifest" / "manifest.csv").read_text()
    assert stats["manifest_sha256"] == hashlib.sha256(manifest.encode()).hexdigest()
    card = (tmp_path / "DATA_CARD.md").read_text()
    assert build.render_counts(stats) in card and card.endswith("tail\n")


# ── committed manifest / stats / data card ────────────────────────────────

def _committed():
    manifest = (DATA / "manifest" / "manifest.csv").read_text()
    stats = json.loads((DATA / "manifest" / "stats.json").read_text())
    rows = list(csv.DictReader(io.StringIO(manifest)))
    return manifest, stats, rows


def test_committed_manifest_matches_stats_and_data_card():
    manifest, stats, rows = _committed()
    assert hashlib.sha256(manifest.encode()).hexdigest() == stats["manifest_sha256"]
    assert len(rows) == stats["total"]
    assert dict(Counter(r["label"] for r in rows)) == {k: v for k, v in stats["by_label"].items() if v}
    for s in SPLITS:
        got = Counter(r["label"] for r in rows if r["split"] == s)
        assert {k: v for k, v in stats["split_counts"][s].items() if v} == dict(got)
    assert sum(r["is_synthetic"] == "True" for r in rows) == stats["synthetic"]
    card = (DATA / "DATA_CARD.md").read_text()
    assert build.render_counts(stats) in card


def test_committed_manifest_has_no_cross_split_leakage():
    _, stats, rows = _committed()
    assert set(stats["leakage"].values()) == {0}
    for key in ("group_id", "near_dup_cluster", "norm_sha256", "synthetic_template"):
        seen = defaultdict(set)
        for r in rows:
            if r[key]:
                seen[r[key]].add(r["split"])
        assert all(len(v) == 1 for v in seen.values()), key
    assert len({r["id"] for r in rows}) == len(rows)


def test_committed_manifest_labels_and_synthetic_share():
    _, stats, rows = _committed()
    for r in rows:
        assert r["label"] == LABEL_MAP[(r["source"], r["original_label"])][0]
        assert (r["is_synthetic"] == "True") == (r["source"] == "synthetic")
    assert stats["synthetic_fraction"] <= MAX_SYNTHETIC_FRACTION
    for lbl, n in stats["by_label"].items():
        real = sum(1 for r in rows if r["label"] == lbl and r["is_synthetic"] == "False")
        if real:  # synthetic never outnumbers real data within a class that has real data
            assert n - real < real


def test_sender_disjoint_subset_has_no_train_sender(built):
    from app.ml.dataset.split import sender_key, shared_domains
    records, _ = built
    shared = shared_domains(records)
    train = {k for r in records if r["split"] == "train" and (k := sender_key(r, shared))}
    for r in records:
        if r["split"] == "train":
            assert r["sender_seen_in_train"] is False
        elif not r["sender_seen_in_train"]:
            assert sender_key(r, shared) not in train
        else:
            assert sender_key(r, shared) in train


def test_committed_train_rows_never_flagged_sender_seen():
    _, stats, rows = _committed()
    assert all(r["sender_seen_in_train"] == "False" for r in rows if r["split"] == "train")
    for s in ("validation", "test"):
        flagged = sum(r["sender_seen_in_train"] == "True" for r in rows if r["split"] == s)
        assert flagged == stats["sender_overlap"][s]["sender_seen_in_train"]
