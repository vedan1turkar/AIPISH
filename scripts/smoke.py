#!/usr/bin/env python3
"""AIPISH end-to-end smoke test against a running Docker Compose demo (through Nginx).

    scripts/demo-up.sh            # start the demo first
    python3 scripts/smoke.py      # then run this (exit status 0 = every check passed)

What it does:
* creates three TEMPORARY accounts (viewer, analyst, admin) with random passwords through the backend CLI
  (`python -m app.cli create-user`, password passed in the process environment, never on a command line),
  and disables them again at the end (`disable-user`), even after a failure;
* never reads .demo/credentials, backend/.dev_credentials or any .env file;
* never calls an external provider: the demo runs with APP_ENV=demo (no live DNS or intel lookups) and
  this script only talks to the local Nginx;
* prints check names and non-sensitive summaries only (no passwords, tokens, e-mail addresses or bodies).

Expected outputs are the synthetic BEC fixture's documented values; ML checks are skipped (reported, not
failed) when the backend reports that no models are mounted.

Environment:
    AIPISH_SMOKE_BASE      base URL (default http://localhost:8080)
    AIPISH_SMOKE_COMPOSE   compose command prefix (default:
                           "docker compose -p aipish-demo -f deploy/docker-compose.yml --env-file deploy/.env")

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = os.environ.get("AIPISH_SMOKE_BASE", "http://localhost:8080").rstrip("/")
COMPOSE = shlex.split(os.environ.get(
    "AIPISH_SMOKE_COMPOSE",
    "docker compose -p aipish-demo -f deploy/docker-compose.yml --env-file deploy/.env"))
API = BASE + "/api/v1"
FIX = ROOT / "backend" / "tests" / "fixtures" / "demo"
BEC = FIX / "bec_wire_change.eml"
LEGIT = FIX / "legitimate_invoice.eml"

# Documented outputs of the synthetic BEC fixture (docs/DEMO_SCRIPT.md).
BEC_RULE_SCORE, BEC_RULE_VERDICT = 100, "phishing_fraud_likely"
BEC_ML_LABEL, BEC_ML_CONF = "impersonated", 0.4355

RESULTS: list[tuple[str, str, str]] = []   # (status, name, detail)


def record(ok: bool | None, name: str, detail: str = "") -> bool:
    status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    RESULTS.append((status, name, detail))
    print(f"[{status}] {name}" + (f": {detail}" if detail else ""), flush=True)
    return bool(ok)


# ── HTTP ────────────────────────────────────────────────────────────────────

class Resp:
    def __init__(self, status: int, headers, body: bytes):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        try:
            return json.loads(self.body or b"null")
        except ValueError:
            return None


def http(method: str, url: str, token: str | None = None, body=None, files=None, timeout=180) -> Resp:
    headers = {"Accept": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if files is not None:
        boundary = uuid.uuid4().hex
        name, filename, content = files
        data = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                f"Content-Type: message/rfc822\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url if url.startswith("http") else API + url, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return Resp(r.status, r.headers, r.read())
    except urllib.error.HTTPError as e:
        return Resp(e.code, e.headers, e.read())


# ── temporary accounts through the CLI ──────────────────────────────────────

def compose_exec(args: list[str], env_extra: dict | None = None, timeout=300) -> subprocess.CompletedProcess:
    env = {**os.environ, **(env_extra or {})}
    flags: list[str] = []
    for k in (env_extra or {}):
        flags += ["-e", k]            # forwarded from this process's environment; the value is not in argv
    return subprocess.run(COMPOSE + ["exec", "-T", *flags, "backend", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=timeout)


def create_user(username: str, role: str) -> str:
    pw = secrets.token_urlsafe(24)
    r = compose_exec(["python", "-m", "app.cli", "create-user", "--username", username, "--role", role],
                     {"AIPISH_NEW_USER_PASSWORD": pw})
    if r.returncode != 0:
        raise RuntimeError(f"create-user {role} failed (exit {r.returncode})")
    return pw


def disable_user(username: str) -> bool:
    r = compose_exec(["python", "-m", "app.cli", "disable-user", "--username", username])
    return r.returncode == 0


def login(username: str, pw: str) -> str | None:
    r = http("POST", "/auth/login", body={"username": username, "password": pw})
    return (r.json() or {}).get("access_token") if r.status == 200 else None


# ── helpers ─────────────────────────────────────────────────────────────────

def upload(token: str, path: Path) -> Resp:
    return http("POST", "/analyses", token, files=("file", path.name, path.read_bytes()))


def find(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def emails_in(text: str) -> set[str]:
    return set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))


# ── checks ──────────────────────────────────────────────────────────────────

def run(tokens: dict[str, str]) -> None:
    viewer, analyst, admin = tokens["viewer"], tokens["analyst"], tokens["admin"]

    # health and readiness (public)
    r = http("GET", "/health")
    record(r.status == 200 and (r.json() or {}).get("status") == "ok", "health", f"HTTP {r.status}")
    r = http("GET", "/health/ready")
    record(r.status == 200 and (r.json() or {}).get("status") == "ok", "readiness", f"HTTP {r.status}")
    info = http("GET", "/system/info", viewer).json() or {}
    record(info.get("environment", info.get("env")) == "demo" or "demo" in json.dumps(info).lower(),
           "system/info reports the demo environment", f"keys={sorted(info)[:6]}")

    # anonymous access is refused
    anon = {p: http("GET", p).status for p in ("/analyses", "/alerts", "/audit/verify", "/campaigns", "/auth/me")}
    record(all(s == 401 for s in anon.values()), "anonymous requests get 401", json.dumps(anon))

    # role permissions
    me = {role: set((http("GET", "/auth/me", t).json() or {}).get("permissions") or []) for role, t in tokens.items()}
    record("pii:view" not in me["viewer"] and "pii:view" in me["analyst"] and "audit:read" in me["admin"]
           and "audit:read" not in me["analyst"], "role permission sets", {k: len(v) for k, v in me.items()}.__repr__())
    perm = {
        "viewer upload -> 403": upload(viewer, LEGIT).status == 403,
        "viewer audit -> 403": http("GET", "/audit/verify", viewer).status == 403,
        "analyst audit -> 403": http("GET", "/audit/verify", analyst).status == 403,
        "analyst admin users -> 403": http("GET", "/admin/users", analyst).status == 403,
        "analyst retention -> 403": http("GET", "/admin/retention/status", analyst).status == 403,
        "admin users -> 200": http("GET", "/admin/users", admin).status == 200,
        "viewer alerts -> 200": http("GET", "/alerts", viewer).status == 200,
        "viewer alert ack -> 403": http("POST", "/alerts/does-not-exist/acknowledge", viewer, body={}).status == 403,
    }
    record(all(perm.values()), "role-based access", ", ".join(k for k, v in perm.items() if not v) or "all as expected")

    # models present?
    mls = http("GET", "/ml/status", viewer).json() or {}
    models = mls.get("status") == "ok"
    record(True, "ML status", f"status={mls.get('status')} model={mls.get('model_version')}")

    # upload BEC and a legitimate sample (analyst)
    r = upload(analyst, BEC)
    bec = r.json() or {}
    if not record(r.status in (200, 201) and bec.get("id"), "upload BEC sample", f"HTTP {r.status}"):
        return
    bec_id = bec["id"]
    det = bec.get("detection") or {}
    record(det.get("score") == BEC_RULE_SCORE and det.get("verdict") == BEC_RULE_VERDICT,
           "BEC rule verdict unchanged", f"score={det.get('score')} verdict={det.get('verdict')}")
    r = upload(analyst, LEGIT)
    leg = r.json() or {}
    record(r.status in (200, 201) and (leg.get("detection") or {}).get("score", 100) < 40,
           "upload legitimate sample", f"HTTP {r.status} score={(leg.get('detection') or {}).get('score')}")
    leg_id = leg.get("id")

    # combined risk (includes the upload-time ML result)
    risk = http("GET", f"/analyses/{bec_id}/risk", viewer).json() or {}
    ml = next((c.get("value") or {} for c in (risk.get("components") or []) if c.get("name") == "ml"), {})
    if models:
        conf = ml.get("confidence")
        record(ml.get("label") == BEC_ML_LABEL and conf is not None and round(float(conf), 4) == BEC_ML_CONF,
               "BEC ML class unchanged", f"label={ml.get('label')} confidence={conf}")
    else:
        record(None, "BEC ML class unchanged", "models not mounted")
    record(risk.get("level") in ("high", "critical") and risk.get("combined_score") is not None, "combined risk",
           f"level={risk.get('level')} score={risk.get('combined_score')} conflict={bool(risk.get('conflict'))}")
    lrisk = http("GET", f"/analyses/{leg_id}/risk", viewer).json() or {} if leg_id else {}
    record(lrisk.get("level") in ("minimal", "low", "MINIMAL", "LOW"), "legitimate sample combined risk",
           f"level={lrisk.get('level')} score={lrisk.get('combined_score')}")

    # ATT&CK
    att = http("GET", f"/analyses/{bec_id}/attack", viewer).json() or {}
    techs = [m.get("technique_id") for m in (att.get("mappings") or [])]
    record(bool(techs), "ATT&CK mapping", f"{len(techs)} technique(s): {', '.join(t for t in techs if t)[:80]}")

    # correlation / campaign C-0001
    camps = http("GET", "/campaigns", viewer).json() or {}
    items = camps.get("items", camps if isinstance(camps, list) else [])
    c1 = next((c for c in items if "C-0001" in str(c.get("label"))), None)
    record(c1 is not None, "campaign C-0001 present",
           f"{len(items)} campaign(s); C-0001 members={c1.get('member_count') if c1 else None}")
    corr = http("GET", f"/analyses/{bec_id}/correlation", viewer)
    record(corr.status == 200, "correlation endpoint", f"HTTP {corr.status}")

    # geo (SIMULATED demo points must be labelled)
    if c1:
        g = http("GET", f"/campaigns/{c1['id']}/geo", viewer).json() or {}
        pts = g.get("points") or g.get("items") or []
        sim = [p for p in pts if p.get("simulated")]
        record(bool(pts) and len(sim) == len(pts), "campaign geo points labelled SIMULATED",
               f"{len(pts)} point(s), {len(sim)} simulated")

    # alerts: one open alert per subject; re-upload increments the occurrence instead of a new alert
    def bec_alerts():
        a = http("GET", "/alerts?page_size=100", viewer).json() or {}
        return [x for x in (a.get("items") or []) if x.get("analysis_id") == bec_id
                or bec_id in json.dumps(x.get("analysis_ids") or [])
                or find(x, "subject_key", default="") and bec.get("raw_sha256", "-") in str(x.get("subject_key"))]
    a = http("GET", "/alerts?page_size=100", viewer).json() or {}
    before = {x["id"]: x.get("occurrence_count", x.get("occurrences")) for x in (a.get("items") or [])}
    r2 = upload(analyst, BEC)
    a2 = http("GET", "/alerts?page_size=100", viewer).json() or {}
    after = {x["id"]: x.get("occurrence_count", x.get("occurrences")) for x in (a2.get("items") or [])}
    new_ids = set(after) - set(before)
    bumped = [i for i in before if after.get(i) is not None and before[i] is not None and after[i] > before[i]]
    record(r2.status in (200, 201) and not new_ids and bool(bumped), "alert dedupe on re-upload",
           f"open alerts={len(after)} new={len(new_ids)} occurrence bumped={len(bumped)}")
    summ = http("GET", "/alerts/summary", viewer)
    record(summ.status == 200, "alert summary", f"HTTP {summ.status}")

    # reports: PDF (via a case) and HTML; viewer copies masked
    case = http("POST", f"/investigations/from-analysis/{bec_id}", analyst, body={}).json() or {}
    case_id = case.get("id") or case.get("case_id")
    pdf_v = http("GET", f"/investigations/{case_id}/report/{bec_id}", viewer)
    record(pdf_v.status == 200 and pdf_v.body[:5] == b"%PDF-", "PDF report download (viewer)",
           f"HTTP {pdf_v.status}, {len(pdf_v.body)} bytes")
    pdf_a = http("GET", f"/investigations/{case_id}/report/{bec_id}", analyst)
    record(pdf_a.status == 200 and pdf_a.body[:5] == b"%PDF-", "PDF report download (analyst)",
           f"HTTP {pdf_a.status}")
    h_v = http("GET", f"/analyses/{bec_id}/report.html", viewer)
    h_a = http("GET", f"/analyses/{bec_id}/report.html", analyst)
    ev, ea = emails_in(h_v.body.decode("utf-8", "ignore")), emails_in(h_a.body.decode("utf-8", "ignore"))
    sender = json.dumps(bec.get("from") or "").lower()
    sender_addr = next(iter(emails_in(sender)), "")
    record(h_v.status == 200 and h_a.status == 200 and sender_addr != "" and sender_addr in {e.lower() for e in ea}
           and sender_addr not in {e.lower() for e in ev}, "HTML report masked for viewer, unmasked for analyst",
           f"viewer addresses={len(ev)} analyst addresses={len(ea)}")
    for label, txt in (("HTML", h_v.body.decode("utf-8", "ignore")),):
        record("not proof of safety" in txt.lower() and "tamper-evident" in txt.lower() and "worm" in txt.lower(),
               f"{label} report carries the safety and custody disclaimers")

    # masking in the API
    av = http("GET", f"/analyses/{bec_id}", viewer).json() or {}
    aa = http("GET", f"/analyses/{bec_id}", analyst).json() or {}
    vs = emails_in(json.dumps(av)); as_ = emails_in(json.dumps(aa))
    record(sender_addr in {e.lower() for e in as_} and sender_addr not in {e.lower() for e in vs},
           "analysis API masks personal data for viewer", f"viewer addresses={len(vs)} analyst addresses={len(as_)}")

    # audit chain, retention dry run
    v = http("GET", "/audit/verify", admin).json() or {}
    record(v.get("ok") is True and not v.get("first_broken_seq"), "audit chain verifies",
           f"checked={v.get('checked')} ok={v.get('ok')}")
    rr = http("POST", "/admin/retention/run", admin, body={"dry_run": True})
    rj = rr.json() or {}
    record(rr.status == 200 and rj.get("dry_run") is True and not rj.get("redacted") and not rj.get("deleted"),
           "retention dry run changes nothing",
           f"HTTP {rr.status} eligible={len(rj.get('eligible_analyses') or [])}")

    # security headers, CSP, no external origins in the SPA shell
    root = http("GET", BASE + "/")
    h = {k.lower(): v for k, v in root.headers.items()}
    csp = h.get("content-security-policy", "")
    need = {"content-security-policy": bool(csp), "x-content-type-options": h.get("x-content-type-options") == "nosniff",
            "x-frame-options": h.get("x-frame-options") == "DENY", "referrer-policy": bool(h.get("referrer-policy"))}
    record(all(need.values()), "security headers on /", ", ".join(k for k, ok in need.items() if not ok) or "present")
    record("connect-src 'self'" in csp and "script-src 'self'" in csp and "unsafe-eval" not in csp,
           "CSP restricts scripts and connections to self")
    api_h = {k.lower(): v for k, v in http("GET", "/auth/me", viewer).headers.items()}
    record("no-store" in api_h.get("cache-control", ""), "API responses are no-store")
    html = root.body.decode("utf-8", "ignore")
    ext = [u for u in re.findall(r"""(?:src|href)=["']([^"']+)["']""", html) if re.match(r"^(https?:)?//", u)]
    record(not ext, "SPA shell loads no external resources", f"{len(ext)} external reference(s)")
    assets = re.findall(r"""(?:src|href)=["'](/assets/[^"']+\.js)["']""", html)
    ext_js = []
    for a_ in assets:
        js = http("GET", BASE + a_).body.decode("utf-8", "ignore")
        ext_js += [u for u in re.findall(r"""fetch\(\s*["'](https?://[^"']+)""", js)]
    record(not ext_js, "frontend bundle has no hard-coded external fetch targets", f"{len(assets)} entry script(s)")

    # models-absent degradation: same classifier code path with no model directory
    r = compose_exec(["python", "-c",
                      "import json;from app.risk.service import _classify;"
                      "print(json.dumps({'status':_classify(open('tests/fixtures/demo/bec_wire_change.eml','rb')"
                      ".read()).get('status')}))"], {"AIPISH_MODEL_DIR": "/nonexistent-models"})
    try:
        st = json.loads(r.stdout.strip().splitlines()[-1]).get("status")
    except (ValueError, IndexError):
        st = f"exit {r.returncode}"
    record(st in ("unavailable", "error"), "models-absent path degrades to an explicit status", f"status={st}")


def main() -> int:
    t0 = time.time()
    suffix = secrets.token_hex(3)
    users = {role: f"smoke-{role}-{suffix}" for role in ("viewer", "analyst", "admin")}
    created: list[str] = []
    try:
        tokens = {}
        for role, name in users.items():
            pw = create_user(name, role)
            created.append(name)
            tok = login(name, pw)
            del pw
            if not record(tok is not None, f"temporary {role} account can sign in"):
                return 1
            tokens[role] = tok
        run(tokens)
    except Exception as exc:  # noqa: BLE001
        record(False, "smoke run aborted", type(exc).__name__ + ": " + str(exc)[:160])
    finally:
        disabled = [n for n in created if disable_user(n)]
        record(len(disabled) == len(created), "temporary accounts disabled", f"{len(disabled)}/{len(created)}")
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    skips = [r for r in RESULTS if r[0] == "SKIP"]
    print(f"\nsmoke: {len(RESULTS) - len(fails) - len(skips)} passed, {len(fails)} failed, {len(skips)} skipped "
          f"in {time.time() - t0:.1f}s")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
