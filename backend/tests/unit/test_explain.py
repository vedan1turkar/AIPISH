"""P2c SHAP explanations: contribution generation, output structure, privacy,
missing models and failure handling. Offline, tiny temp model (LR + XGBoost)."""
from __future__ import annotations

import json
import shutil
from email.message import EmailMessage

import pytest

pytest.importorskip("shap")
pytest.importorskip("xgboost")

from fastapi.testclient import TestClient  # noqa: E402
from test_ml import _corpus, _train_bundle  # noqa: E402  (same test dir)

from app.main import create_app  # noqa: E402
from app.ml import explain as X  # noqa: E402
from app.ml import features as F  # noqa: E402
from app.ml import inference  # noqa: E402
from app.ml.dataset import build  # noqa: E402

SECRET_NAME = "zyxwquorble"
PHISH_RAW = None


def _eml(frm, subject, body):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "victim.person@corp.test", subject
    m.set_content(body)
    return bytes(m)


RAW = _eml("Bank <alert@bank.test>", "verify your account",
           f"Dear {SECRET_NAME}, your account is suspended. Verify your password at "
           "http://login-portal.example/verify immediately or contact help@bank.test.")


@pytest.fixture(scope="module")
def model(tmp_path_factory):
    records, _ = build.prepare(_corpus())
    dets = {r["id"]: {"score": 0, "verdict": "minimal", "findings": []} for r in records}
    path = _train_bundle(records, dets, tmp_path_factory.mktemp("m"))
    cfg = json.loads((path / "model_config.json").read_text())
    cfg["dataset"]["by_split"] = {"train": sum(r["split"] == "train" for r in records)}
    (path / "model_config.json").write_text(json.dumps(cfg))
    return path


@pytest.fixture
def use(monkeypatch):
    def _use(path):
        monkeypatch.setenv("AIPISH_MODEL_DIR", str(path))
        inference.reset_classifier_cache()
    yield _use
    inference.reset_classifier_cache()


def test_explanation_structure_and_additivity(model, use):
    use(model)
    out = X.explain_raw(RAW)
    assert out["status"] == "ok" and out["method"] == "SHAP"
    assert out["explained_label"] == inference.classify_raw(RAW).label
    assert set(out["components"]) == {"lr", "xgb"}
    assert "not causal" in out["disclaimer"]
    for name, comp in out["components"].items():
        assert comp["additivity_ok"], name           # base + sum(SHAP) == model output
        assert comp["ensemble_weight"] == 0.5
        for row in comp["top_contributions"]:
            assert set(row) >= {"feature", "group", "shap_value", "direction"}
            assert row["direction"] == ("toward" if row["shap_value"] > 0 else "away")
        vals = [abs(r["shap_value"]) for r in comp["top_contributions"]]
        assert vals == sorted(vals, reverse=True) and len(vals) <= X.TOP_K


def test_xgb_shap_matches_xgboost_native_contributions(model, use):
    import numpy as np
    from xgboost import DMatrix
    use(model)
    clf, _ = inference.get_classifier()
    rec, det = F.record_from_raw(RAW), F.run_rules_offline(RAW)
    label = clf.predict_record(rec, det).label
    exp = X.explain_xgb(clf, rec, det, label, top_k=200)
    Xm = clf.fz.transform([rec], [det])
    native = clf.xgb.get_booster().predict(DMatrix(Xm), pred_contribs=True)[0]
    k = clf.xgb_classes.index(label)
    native_k = np.asarray(native)[k] if np.ndim(native) == 2 else np.asarray(native).reshape(-1, len(clf.xgb_classes))[:, k]
    by_name = {r["feature"]: r["shap_value"] for r in exp["top_contributions"]}
    for i, name in enumerate(clf.fz.names[:len(F.STRUCTURED_NAMES) + len(F.RULE_FEATURE_NAMES)]):
        if name in by_name:
            assert abs(by_name[name] - float(native_k[i])) < 1e-3


def test_lr_shap_equals_weight_times_tfidf(model, use):
    import numpy as np
    use(model)
    clf, _ = inference.get_classifier()
    rec = F.record_from_raw(RAW)
    label = clf.predict_record(rec, F.run_rules_offline(RAW)).label
    exp = X.explain_lr(clf, rec, label, top_k=500)
    tfidf, lr = clf.lr.named_steps["tfidf"], clf.lr.named_steps["clf"]
    Xv = tfidf.transform([F.text_input(rec)])
    k = list(clf.lr.classes_).index(label)
    names = list(tfidf.get_feature_names_out())
    for row in exp["top_contributions"]:
        j = names.index("word__" + row["feature"].split(":", 1)[1])
        assert abs(row["shap_value"] - float(lr.coef_[k, j] * Xv[0, j])) < 1e-4
    total = sum(r["shap_value"] for r in exp["top_contributions"]) + sum(
        a["shap_value"] for a in exp["aggregated"])
    assert abs(exp["base_value"] + total - exp["output_value"]) < 1e-2
    assert np.isclose(exp["base_value"], lr.intercept_[k], atol=1e-4)


def test_explanations_never_contain_raw_content(model, use):
    use(model)
    blob = json.dumps(X.explain_raw(RAW)).lower()
    for secret in (SECRET_NAME, "victim.person", "help@bank.test", "login-portal", "http"):
        assert secret not in blob
    lr = X.explain_raw(RAW)["components"]["lr"]
    assert lr["redaction"]["withheld_terms"] >= 1      # the rare name was withheld
    assert all(r["feature"].startswith("term:") for r in lr["top_contributions"])


def test_rule_engine_features_are_explained_not_replaced(model, use):
    use(model)
    c = TestClient(create_app())
    body = c.post("/api/v1/ml/explain", files={"file": ("m.eml", RAW, "message/rfc822")}).json()
    assert body["explanation"]["status"] == "ok"
    assert body["ml"]["status"] == "ok" and body["ml"]["label"] == body["explanation"]["explained_label"]
    assert {"score", "verdict", "fired"} <= set(body["rules"])          # 18-rule output intact
    groups = {r["group"] for r in body["explanation"]["components"]["xgb"]["top_contributions"]}
    assert groups <= {"structural", "rule_engine"}


def test_missing_model_gives_unavailable_without_contributions(tmp_path, use):
    use(tmp_path / "none")
    out = X.explain_raw(RAW)
    assert out["status"] == "unavailable" and out["components"] == {} and "missing" in out["reason"]
    body = TestClient(create_app()).post(
        "/api/v1/ml/explain", files={"file": ("m.eml", RAW, "message/rfc822")}).json()
    assert body["explanation"]["status"] == "unavailable" and body["ml"]["label"] is None


def test_shap_not_installed_is_unavailable(model, use, monkeypatch):
    use(model)

    def boom():
        raise X.ExplainUnavailable("SHAP not installed; see requirements-ml.txt")

    monkeypatch.setattr(X, "_shap", boom)
    out = X.explain_raw(RAW)
    assert out["status"] == "unavailable" and out["components"] == {}


def test_shap_failure_is_error_without_contributions(model, use, monkeypatch):
    use(model)

    def broken(*a, **k):
        raise RuntimeError("tree walk failed")

    monkeypatch.setattr(X, "explain_record", broken)
    out = X.explain_raw(RAW)
    assert out["status"] == "error" and out["components"] == {}
    assert "RuntimeError" in out["reason"]


def test_unsupported_input_is_not_applicable(model, use):
    use(model)
    out = X.explain_raw(_eml("a@b.test", "x", "hi"))
    assert out["status"] == "not_applicable" and out["components"] == {}


def test_one_component_failing_is_reported_not_hidden(model, use, monkeypatch):
    use(model)

    def no_lr(*a, **k):
        raise X.ExplainUnavailable("lr explainer unavailable")

    monkeypatch.setattr(X, "explain_lr", no_lr)
    out = X.explain_raw(RAW)
    assert out["status"] == "ok" and set(out["components"]) == {"xgb"}
    assert out["not_explained"] == [{"component": "lr", "reason": "lr explainer unavailable"}]


def test_corrupt_model_unavailable(model, tmp_path, use):
    bad = tmp_path / "bad"
    shutil.copytree(model, bad)
    (bad / "lr_pipeline.joblib").write_bytes(b"junk")
    use(bad)
    assert X.explain_raw(RAW)["status"] == "unavailable"
