"""P2b ML pipeline: preprocessing, label mapping, metrics, model I/O, inference
format, missing-model handling and reproducibility. Offline; uses a tiny model
trained in a temp dir (LR + XGBoost only; the DistilRoBERTa component is
exercised by the real training run, not by unit tests)."""
from __future__ import annotations

import json
import math
import random
from email.message import EmailMessage
from pathlib import Path

import pytest

pytest.importorskip("sklearn")
pytest.importorskip("xgboost")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402
from tests.authutil import authed_client  # noqa: E402
from app.ml import features as F  # noqa: E402
from app.ml import inference  # noqa: E402
from app.ml import train as T  # noqa: E402
from app.ml.dataset import build, synthetic  # noqa: E402
from app.ml.dataset.labels import LABELS  # noqa: E402
from app.ml.dataset.normalize import RawMessage  # noqa: E402
from app.ml.metrics import binary_report, classification_report, confusion  # noqa: E402

TINY_CFG = json.loads(json.dumps(T.DEFAULT_CONFIG))
TINY_CFG["lr"].update(word_max_features=2000, char_max_features=2000, min_df=1, max_iter=500)
TINY_CFG["svd_components"] = 8
TINY_CFG["xgb"].update(n_estimators=40, early_stopping_rounds=10, n_jobs=1)

WORDS = ("meeting schedule report budget project review agenda notes draft team quarterly "
         "shipment contract invoice lunch update deadline forecast minutes summary").split()
PHISH = ("verify account suspended password login confirm security bank update click "
         "immediately locked identity billing").split()


def _eml(frm, subject, body):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "user@corp.test", subject
    m["Date"] = "Tue, 05 Mar 2002 10:00:00 +0000"
    m.set_content(body)
    return bytes(m)


def _corpus() -> list[RawMessage]:
    rng = random.Random(3)
    msgs = []
    for i in range(80):
        body = " ".join(rng.choice(WORDS) for _ in range(40))
        msgs.append(RawMessage("spamassassin", "fx", f"h/{i}", "easy_ham",
                               _eml(f"P{i} <p{i}@host{i}.test>", f"{rng.choice(WORDS)} {i}", body)))
        body = " ".join(rng.choice(PHISH) for _ in range(30)) + f" http://login-{i}.example/verify"
        msgs.append(RawMessage("nazario", "fx", f"p#{i}", "phishing",
                               _eml(f"Bank <alert@bank{i}.test>", f"{rng.choice(PHISH)} {i}", body)))
    return msgs + synthetic.generate(per_template=6)


@pytest.fixture(scope="module")
def tiny_data():
    records, _ = build.prepare(_corpus())
    dets = {r["id"]: {"score": 0, "verdict": "minimal", "findings": []} for r in records}
    return records, dets


def _train_bundle(records, dets, out_dir: Path) -> Path:
    import joblib
    tr = [r for r in records if r["split"] == "train"]
    va = [r for r in records if r["split"] == "validation"]
    lr = T.train_lr([F.text_input(r) for r in tr], [r["label"] for r in tr], TINY_CFG)
    fz = T.XgbFeaturizer(TINY_CFG).fit(tr, [dets[r["id"]] for r in tr])
    xgb, classes = T.train_xgb(fz.transform(tr, [dets[r["id"]] for r in tr]), [r["label"] for r in tr],
                               fz.transform(va, [dets[r["id"]] for r in va]), [r["label"] for r in va],
                               TINY_CFG)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(lr, out_dir / "lr_pipeline.joblib")
    joblib.dump(fz, out_dir / "xgb_featurizer.joblib")
    xgb.save_model(out_dir / "xgb_model.json")
    trained = [lbl for lbl in LABELS if lbl in {r["label"] for r in tr}]
    (out_dir / "model_config.json").write_text(json.dumps({
        "model_name": "tiny-test", "created_utc": "2026-11-19T00:00:00+00:00",
        "dataset": {"manifest_sha256": "0" * 64}, "labels": list(LABELS),
        "trained_classes": trained, "untrained_classes": [x for x in LABELS if x not in trained],
        "config": TINY_CFG, "ensemble_weights": {"lr": 0.5, "xgb": 0.5},
        "xgb": {"classes": classes}}))
    return out_dir


@pytest.fixture(scope="module")
def tiny_model(tiny_data, tmp_path_factory):
    return _train_bundle(*tiny_data, tmp_path_factory.mktemp("model"))


@pytest.fixture
def use_model(monkeypatch):
    def _use(path):
        monkeypatch.setenv("AIPISH_MODEL_DIR", str(path))
        inference.reset_classifier_cache()
    yield _use
    inference.reset_classifier_cache()


# ── preprocessing ─────────────────────────────────────────────────────────

def test_record_from_raw_matches_corpus_normalisation():
    raw = _eml("A <a@b.test>", "Verify now", "Please verify your account at http://x.example/login "
               "or email help@x.example today, thank you very much.")
    rec = F.record_from_raw(raw)
    assert "<URL>" in rec["body"] and "<EMAIL>" in rec["body"] and "http" not in rec["body"]
    assert F.text_input(rec).startswith("Verify now\n\n")
    assert rec["url_hosts"] == ["x.example"]


def test_structured_and_rule_features_shape():
    rec = F.record_from_raw(_eml("A <a@b.test>", "HELLO!!", "Go to http://192.0.2.5/x now please, "
                                                            "this body is long enough."))
    s = F.structured_features(rec)
    assert len(s) == len(F.STRUCTURED_NAMES)
    named = dict(zip(F.STRUCTURED_NAMES, s, strict=True))
    assert named["url_ip_host"] == 1.0 and named["has_url"] == 1.0 and named["exclaim_count"] >= 2
    assert len(F.RULE_IDS) == 18
    det = {"score": 30, "findings": [{"rule_id": "ip_literal_url", "contribution": 30}]}
    r = F.rule_features(det)
    assert len(r) == 19 and r[F.RULE_IDS.index("ip_literal_url")] == 30.0 and r[-1] == 30.0


def test_rule_engine_failure_gives_missing_not_zero():
    r = F.rule_features({"error": "AttributeError: x"})
    assert len(r) == 19 and all(math.isnan(v) for v in r)


def test_rules_offline_runs_on_raw_bytes():
    det = F.run_rules_offline(_eml("A <a@b.test>", "URGENT verify", "Act now: http://192.0.2.5/login "
                                                                     "verify your password immediately."))
    assert "error" not in det and 0 <= det["score"] <= 100
    assert "ip_literal_url" in {f["rule_id"] for f in det["findings"]}


# ── label mapping ─────────────────────────────────────────────────────────

def test_expand_maps_trained_columns_to_full_taxonomy():
    full = T._expand([[0.2, 0.3, 0.5]], ["legitimate", "phishing", "fraud"])[0]
    assert full == [0.2, 0.0, 0.0, 0.3, 0.5]
    assert T.argmax_labels([full]) == ["fraud"]


def test_rules_binary_mapping():
    dets = [{"verdict": "minimal"}, {"verdict": "suspicious"}, {"verdict": "phishing_fraud_likely"},
            {"error": "x"}]
    assert T.rules_binary_pred(dets, strict=False) == ["legitimate", "phishing", "phishing", "legitimate"]
    assert T.rules_binary_pred(dets, strict=True) == ["legitimate", "legitimate", "phishing", "legitimate"]


# ── metrics ───────────────────────────────────────────────────────────────

def test_classification_report_hand_computed():
    y = ["legitimate", "legitimate", "phishing", "phishing", "fraud"]
    p = ["legitimate", "phishing", "phishing", "phishing", "legitimate"]
    rep = classification_report(y, p)
    leg, ph, fr = (rep["per_class"][k] for k in ("legitimate", "phishing", "fraud"))
    assert (leg["precision"], leg["recall"], leg["f1"]) == (0.5, 0.5, 0.5)
    assert (ph["precision"], ph["recall"], ph["f1"]) == (0.6667, 1.0, 0.8)
    assert (fr["precision"], fr["recall"], fr["f1"]) == (0.0, 0.0, 0.0)
    assert rep["per_class"]["suspicious"]["f1"] is None            # no support -> not evaluated
    assert rep["evaluated_classes"] == ["legitimate", "phishing", "fraud"]
    assert rep["macro_f1"] == round((0.5 + 0.8 + 0.0) / 3, 4)
    assert rep["accuracy"] == 0.6
    assert rep["weighted_f1"] == round((0.5 * 2 + 0.8 * 2 + 0.0 * 1) / 5, 4)   # support-weighted
    assert rep["weighted_recall"] == rep["accuracy"]
    assert confusion(y, p)[LABELS.index("phishing")][LABELS.index("phishing")] == 2


def test_binary_report_groups_threat_classes():
    rep = binary_report(["fraud", "phishing", "legitimate"], ["phishing", "legitimate", "legitimate"])
    assert rep["per_class"]["threat"]["recall"] == 0.5
    assert rep["per_class"]["threat"]["precision"] == 1.0


def test_ensemble_weight_grid_sums_to_one():
    comps = {"a": [[1, 0, 0, 0, 0]], "b": [[0, 0, 0, 1, 0]]}
    w, f1 = T.pick_ensemble_weights(comps, ["phishing"], 0.25)
    assert abs(sum(w.values()) - 1) < 1e-9 and f1 == 1.0 and w["b"] > w["a"]


# ── dataset validation before training ────────────────────────────────────

def test_validate_dataset_accepts_consistent_build(tmp_path, tiny_data):
    records, excluded = build.prepare(_corpus())
    build.write_outputs(records, excluded, tmp_path)
    version, recs = T.validate_dataset(tmp_path)
    assert version["total"] == len(recs) == len(records)


def test_validate_dataset_rejects_tampering(tmp_path):
    records, excluded = build.prepare(_corpus())
    build.write_outputs(records, excluded, tmp_path)
    p = tmp_path / "processed" / "emails.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["split"] = "test" if rec["split"] != "test" else "train"
    p.write_text("\n".join([json.dumps(rec)] + lines[1:]) + "\n")
    with pytest.raises(T.DatasetError):
        T.validate_dataset(tmp_path)
    (tmp_path / "processed" / "emails.jsonl").unlink()
    with pytest.raises(T.DatasetError):
        T.validate_dataset(tmp_path)


# ── model input/output, inference format ──────────────────────────────────

def test_inference_output_format(tiny_model, use_model):
    use_model(tiny_model)
    res = inference.classify_raw(_eml("Bank <x@bank.test>", "verify your account",
                                      "Your account is suspended, verify your password at "
                                      "http://login.example/verify immediately."))
    d = res.to_dict()
    assert d["status"] == "ok" and d["label"] in LABELS
    assert set(d["probabilities"]) == set(LABELS)
    assert abs(sum(d["probabilities"].values()) - 1) < 1e-3
    assert d["probabilities"]["suspicious"] == 0.0 and "suspicious" in d["untrained_classes"]
    assert set(d["components"]) == {"lr", "xgb"}
    assert d["confidence"] == max(d["probabilities"].values())
    assert d["model_version"].startswith("tiny-test@")


def test_tiny_model_learns_signal(tiny_model, use_model, tiny_data):
    use_model(tiny_model)
    clf, _ = inference.get_classifier()
    records, dets = tiny_data
    test = [r for r in records if r["split"] == "test" and not r["is_synthetic"]]
    preds = [clf.predict_record(r, dets[r["id"]]).label for r in test]
    acc = sum(p == r["label"] for p, r in zip(preds, test, strict=True)) / len(test)
    assert acc > 0.9  # trivially separable fixture; checks wiring, not real accuracy


def test_out_of_scope_message_is_not_applicable(tiny_model, use_model):
    use_model(tiny_model)
    res = inference.classify_raw(_eml("a@b.test", "x", "hi"))
    assert res.status == "not_applicable" and res.label is None


def test_api_classify_and_status_with_model(tiny_model, use_model):
    use_model(tiny_model)
    c = authed_client()
    assert c.get("/api/v1/ml/status").json()["status"] == "ok"
    raw = _eml("Bank <x@bank.test>", "verify", "Verify your account at http://login.example/x now please.")
    body = c.post("/api/v1/ml/classify", files={"file": ("m.eml", raw, "message/rfc822")}).json()
    assert body["ml"]["status"] == "ok" and body["ml"]["label"] in LABELS
    assert {"score", "verdict", "fired"} <= set(body["rules"])


# ── missing / broken model handling ───────────────────────────────────────

def test_missing_model_is_unavailable_not_legitimate(tmp_path, use_model):
    use_model(tmp_path / "nope")
    res = inference.classify_raw(_eml("a@b.test", "hello", "A perfectly ordinary message body here."))
    assert res.status == "unavailable" and res.label is None and res.probabilities == {}
    assert "missing" in res.reason


def test_corrupt_model_is_unavailable(tiny_model, tmp_path, use_model):
    import shutil
    bad = tmp_path / "bad"
    shutil.copytree(tiny_model, bad)
    (bad / "xgb_model.json").write_text("not a model")
    use_model(bad)
    res = inference.classify_raw(_eml("a@b.test", "hello", "A perfectly ordinary message body here."))
    assert res.status == "unavailable" and res.label is None and "failed to load" in res.reason


def test_label_order_mismatch_is_rejected(tiny_model, tmp_path, use_model):
    import shutil
    bad = tmp_path / "order"
    shutil.copytree(tiny_model, bad)
    cfg = json.loads((bad / "model_config.json").read_text())
    cfg["labels"] = list(reversed(cfg["labels"]))
    (bad / "model_config.json").write_text(json.dumps(cfg))
    use_model(bad)
    assert inference.classify_raw(_eml("a@b.test", "s", "Body text that is long enough.")).status == "unavailable"


def test_api_without_model(tmp_path, use_model):
    use_model(tmp_path / "nope")
    c = authed_client()
    assert c.get("/api/v1/ml/status").json()["status"] == "unavailable"
    raw = _eml("a@b.test", "hello", "A perfectly ordinary message body here.")
    body = c.post("/api/v1/ml/classify", files={"file": ("m.eml", raw, "message/rfc822")}).json()
    assert body["ml"]["status"] == "unavailable" and body["ml"]["label"] is None
    assert body["rules"]["verdict"] in {"minimal", "suspicious", "phishing_fraud_likely"}


# ── reproducibility ───────────────────────────────────────────────────────

def test_training_is_reproducible(tiny_data, tmp_path):
    records, dets = tiny_data
    a = _train_bundle(records, dets, tmp_path / "a")
    b = _train_bundle(records, dets, tmp_path / "b")
    test = [r for r in records if r["split"] == "test"]
    pa = inference.EmailClassifier(a)
    pb = inference.EmailClassifier(b)
    for r in test[:20]:
        assert pa.predict_record(r, dets[r["id"]]).probabilities == \
            pb.predict_record(r, dets[r["id"]]).probabilities


def test_never_trains_on_validation_or_test():
    """In main(), every fit call receives train-split data only (val = selection only)."""
    src = Path(T.__file__).read_text()
    assert 'train_lr(texts["train"], ys["train"], cfg)' in src
    assert 'XgbFeaturizer(cfg).fit(split["train"], sdet["train"])' in src
    assert 'train_xgb(X["train"], ys["train"], X["validation"]' in src
    assert 'fine_tune(texts["train"]' in src
    # lr pipeline, featurizer, xgb - each audited above (svd is fitted inside the featurizer)
    assert src.count(".fit(") == 3


def test_pickled_classes_live_in_importable_modules():
    from app.ml.featurizer import XgbFeaturizer
    assert T.XgbFeaturizer is XgbFeaturizer
    assert XgbFeaturizer.__module__ == "app.ml.featurizer"  # never __main__ (unloadable pickle)


# ── post-hoc evaluation helpers (app.ml.evaluate) ─────────────────────────

def test_class_inventory_flags_zero_and_synthetic_only(tiny_data):
    from app.ml.evaluate import class_inventory
    records, _ = tiny_data
    inv = class_inventory(records)
    assert inv["zero_sample_classes"] == ["suspicious"]
    assert set(inv["synthetic_only_training_classes"]) == {"impersonated", "fraud"}
    for s in ("train", "validation", "test"):
        for c in inv["counts"][s].values():
            assert c["total"] == c["real"] + c["synthetic"]


def test_leakage_audit_passes_and_detects_overlap(tiny_data):
    from app.ml.evaluate import leakage_audit
    records, _ = tiny_data
    sizes = {s: sum(r["split"] == s for r in records) for s in ("train", "validation", "test")}
    cfg = {"dataset": {"manifest_sha256": "abc", "by_split": sizes}}
    ok = leakage_audit(records, cfg, "abc")
    assert ok["passed"] and ok["all_overlaps_zero"] and all(ok["code_audit"].values())
    leaked = [dict(r) for r in records]
    victim = next(r for r in leaked if r["split"] == "test")
    twin = next(r for r in leaked if r["split"] == "train")
    victim["norm_sha256"] = twin["norm_sha256"]          # same text in train and test
    bad = leakage_audit(leaked, cfg, "abc")
    assert not bad["passed"] and bad["overlaps"]["norm_sha256_overlap"]["train&test"] == 1
    assert not leakage_audit(records, cfg, "other")["passed"]   # wrong dataset version
