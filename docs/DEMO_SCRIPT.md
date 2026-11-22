# AIPISH demo script (about 12 minutes)

Every number below comes from runs in the P5z release task (2026-11-22, Apple M4, Docker Desktop, host
Ollama with `mistral`, models mounted): a pristine `scripts/demo-up.sh` boot captured by API, plus
`scripts/smoke.py`. If a number differs on your machine, say so rather than quoting this page.

All demo data is **synthetic**. Domains use `.example` / `.test`; no real people or organisations.

## Pre-demo checklist (do this 15 minutes before)

| Check | How | Expected |
|---|---|---|
| Docker Desktop is running | `docker info` | No error |
| Disk space | About 5 GB free for images | Backend image 2.26 GB, web 85.2 MB |
| Ollama is running with `mistral` | `curl -s localhost:11434/api/tags` | Lists `mistral:latest` |
| Models are present | `ls models/aipish-email-v1` | Model directory exists (gitignored, mounted read-only) |
| Port 8080 is free | `lsof -i :8080` | Nothing listening |
| Fresh demo | `scripts/demo-reset.sh --up` | `AIPISH demo is running: http://localhost:8080`; ~95–99 s after the images exist |
| Credentials | `.demo/credentials` (gitignored, mode 0600; the script prints only the path) | `demo-admin`, `demo-analyst`, `demo-viewer` |
| Smoke test | `python3 scripts/smoke.py` | `smoke: 36 passed, 0 failed` (creates and disables its own temporary accounts) |

Run the smoke test **before** a fresh reset if you want pristine alert counts on stage, because it uploads the
BEC sample again (the BEC alert's occurrence count goes up).

Open http://localhost:8080 in a browser at 1440 px or wider.

## 1. Sign in and roles (1 min) — `demo-viewer`, then `demo-analyst`

1. Sign in as **demo-viewer**. The navigation shows Overview, History, Alerts, Campaigns, Analytics, Search.
   There is no Analyse, Users, Audit or Retention.
2. Sign out, sign in as **demo-analyst**. Analyse appears.

> *Speaker note:* local accounts with JWT; three global roles (viewer, analyst, admin). The backend enforces
> a deny-by-default route map; the UI only hides what the role cannot use. No OAuth or SSO.

## 2. Overview (1 min) — analyst

Point at the counts: **8 analyses** (6 `phishing_fraud_likely`, 2 `minimal`), **7 new alerts**
(1 critical, 5 high, 1 medium), **1 candidate campaign** (C-0001).

> *Speaker note:* everything here comes from the backend. Scores are investigative indicators, not proof.

## 3. The BEC sample and the verdict strip (2 min) — analyst

History → **Confidential: urgent supplier wire change**. Read the strip left to right:

| Panel | Value | What it means |
|---|---|---|
| Rule engine | **100 · PHISHING FRAUD LIKELY** | 18 deterministic rules. Fired here: Reply-To differs from sender domain, payment-diversion/BEC language, header inconsistencies, urgency language. |
| ML classifier | **IMPERSONATED 0.4355** | Separate statistical model (`aipish-email-v1`). 0.4355 is the uncalibrated probability of the top class; fraud is next at 0.2929. |
| Combined risk | **80 · HIGH**, confidence medium | An index combining rules, ML, hard evidence, intel, campaign and ATT&CK. Not a probability. |

> *Speaker note:* the three are shown side by side on purpose; none overrides another. The ML threat index is
> 1 − P(legitimate) = 0.8208. The model was trained on old corpora, and its impersonated/fraud classes are
> synthetic, so 0.4355 is a model score, not a likelihood of fraud.

## 4. Headers and relay trace (1 min)

Tabs **Headers & relay**, then **Trace view**.

> *Speaker note:* this sample has no public relay hop, so there is no origin IP. Received headers before the
> trusted boundary can be forged; an origin IP is a candidate, never a person or location. The Headers tab
> also shows the informational mail-parser cross-check.

## 5. AI assessment (1.5 min)

Tab **AI assessment** (generated during `demo-up`: ML ok, SHAP ok, LLM ok).

> *Speaker note:* SHAP explains the **XGBoost component only**. DistilRoBERTa has 50 % of the ensemble weight
> and is not explained, so these SHAP values do not explain the ensemble decision. The Mistral summary runs
> locally through Ollama; its findings must cite evidence IDs, and its recommendations are mapped to fixed,
> pre-approved templates. Generating a new assessment takes about 85 s on this machine, so do not click it live.

## 6. Threat intel (1 min)

Tab **Threat intel** (status: not run).

> *Speaker note:* lookups are opt-in per analysis, need explicit consent, and send bare indicators only
> (IPs, domains, attachment hashes), never message content. The demo runs with `APP_ENV=demo`, so it makes no
> live lookups; demo map data is labelled SIMULATED. Live lookups were verified once (2026-11-22) for the
> approved indicators only: 8.8.8.8, 1.1.1.1, example.com and the EICAR hash
> ([intel/LIVE_VERIFICATION.md](intel/LIVE_VERIFICATION.md)). Absence of reports is not proof of safety.

## 7. Correlation and campaign C-0001 (1.5 min)

**Campaigns → C-0001**: *Candidate campaign C-0001, medium confidence (0.82), 4 analyses*. Show the graph and
"Why these analyses are grouped": public IP `96.7.128.175` (medium) and Reply-To domain
`vendor-remit-portal.test` (medium) shared by all four, display name "accounts payable desk" (weak).

Then open **[SYNTHETIC DEMO] Community garden meeting on Saturday** → tab **Related**.

> *Speaker note:* that message shares only `outlook.com`, which is stop-listed as generic provider
> infrastructure, so it is deliberately **not** linked. A candidate campaign groups shared technical
> indicators; it does not identify a sender, attacker or person. Weights were tuned on synthetic data.

## 8. ATT&CK and source type (1 min)

Back to the BEC sample → tab **ATT&CK**: **T1684.001** Social Engineering: Impersonation (medium),
**T1657** Financial Theft (medium), **T1585.002** Establish Accounts: Email Accounts (low). Source type:
**undetermined** (no likely or possible hypothesis).

> *Speaker note:* ATT&CK Enterprise 20.1. These are single-message approximations from this email's evidence,
> not observed adversary behaviour.

## 9. Geo map (0.5 min)

Campaign C-0001 page, map section: the point is labelled **SIMULATED DEMO DATA**.

> *Speaker note:* infrastructure location only, approximate; VPN, hosting, Tor and anycast distort it. The
> demo uses simulated points. One real IPinfo point (8.8.8.8, anycast) was verified during the live run, not
> in the demo.

## 10. Alerts and lifecycle (1 min)

**Alerts**: 7 new. Open **New candidate campaign: C-0001** → **Acknowledge** → **Resolve…** (a note is
required) → **Reopen**. The history lists each step with the user.

> *Speaker note:* alerts are raised when an analysis is processed; there is no mailbox monitoring. One open
> alert per subject: re-uploading the BEC sample increments its occurrence count instead of creating a new
> alert (checked by the smoke test).

## 11. Reports and viewer masking (1 min)

On the BEC sample: **Create investigation case**, then **Download forensic PDF** and **Download HTML
report**. Sign in as **demo-viewer** and open the same analysis.

> *Speaker note:* the viewer sees partially masked addresses (for example `d***@internal-corp.example`) and no
> display names or bodies; the viewer's PDF is labelled MASKED VIEW. **Subjects are not masked.** Section 9 of
> the report states the custody limits: SHA-256 detects change to the stored evidence file; the audit log is a
> tamper-evident HMAC hash chain, not tamper-proof; no WORM storage. With the default hash-only policy the
> integrity check reports *Unavailable*, because the raw bytes are not kept.

## 12. Audit chain (1 min) — `demo-admin`

**Audit → Verify now**: *CHAIN OK*. Pristine demo: 24 events checked
(`python -m app.cli audit-verify` prints `chain: OK  events checked: N`).

**Tamper demonstration (describe, or run only on the demo database, then reset).** It was *not* run in the
P5z task; the expected output comes from `backend/tests/unit/test_audit.py` and
[audit/README.md](audit/README.md):

1. In a terminal: `docker compose -p aipish-demo -f deploy/docker-compose.yml --env-file deploy/.env exec postgres psql -U aipish -d aipish`
2. Bypass the append-only trigger as the table owner and change one event, for example
   `ALTER TABLE audit_event DISABLE TRIGGER USER;` then an `UPDATE audit_event SET detail = ... WHERE seq = 5;`
   then `ALTER TABLE audit_event ENABLE TRIGGER USER;`
3. **Verify now** reports the chain as broken at seq 5 with
   `event_hash mismatch: the event content was changed`.
4. Run `scripts/demo-reset.sh --up` afterwards: the chain stays broken until the demo database is recreated.
   **Never do this on any database other than the demo.**

> *Speaker note:* this shows tamper evidence, not prevention. Someone with database write access and the
> audit key could forge a consistent chain; external checkpoints (**Create checkpoint**) reduce that risk.

## 13. Retention dry run (0.5 min) — admin

**Retention → Preview (dry run)**: *Dry run: nothing changed. 0 eligible, 0 evidence-only, 0 held.* Policy is
disabled by default.

> *Speaker note:* redact or delete with legal holds; audit events are never purged; there is no built-in
> scheduler (cron or the Compose `retention` profile).

## Do not claim

- That AIPISH identifies an attacker, a person or a physical location.
- That a low score, `minimal`, "no record" or "no flags" means a message is safe.
- That the ML model is "accurate" or "validated" for real mail; quote the test-split numbers with their
  caveats ([LIMITATIONS.md](LIMITATIONS.md)).
- That SHAP explains the ensemble, or that the risk index is a probability.
- That the audit log is tamper-proof or immutable, or that WORM storage is used.
- Real-time monitoring, mailbox integration, OAuth/SSO, MISP or MaxMind.
- That threat-intel provider error paths were verified live.

## Fallbacks

| Problem | What to do |
|---|---|
| Ollama not running | The AI assessment shows UNAVAILABLE; everything else works. Say so and continue. Restart with `ollama serve`, then `scripts/demo-reset.sh --up` to regenerate the stored assessment. |
| Models missing | ML shows `unavailable` everywhere (the smoke test checks this path); rules, risk (without ML), ATT&CK and campaigns still work. |
| Docker misbehaves | `scripts/demo-reset.sh --up`. If images are missing, the first build takes about 3–4 minutes (backend 191 s, web 20 s here). |
| Port 8080 busy | `AIPISH_DEMO_PORT=8081 scripts/demo-up.sh` |
| Lost credentials | `.demo/credentials`; or `scripts/demo-reset.sh --up` re-issues them |

## After the demo

```bash
scripts/demo-reset.sh
```

This stops the demo stack and deletes its volumes and `.demo/credentials`. Images remain; remove them with
`docker image rm aipish-backend:local aipish-web:local` if needed.
