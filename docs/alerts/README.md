# Risk-based alerts (P5f)

> **Alerts are raised when an analysis is processed; this system does not monitor mailboxes in real time.**
> There is no IMAP or Microsoft Graph ingestion (R36). An alert appears only after an analysis is uploaded,
> recomputed or correlated into a campaign.

Code:

- `backend/app/alerts/service.py`: rules, dedupe, lifecycle and transitions.
- `backend/app/alerts/notify.py`: optional e-mail.
- `backend/app/alerts/config.py`: settings.
- `backend/app/api/alerts_router.py`: the API.
- `frontend/src/components/alerts/`: the UI.

## 1. Data

**`alert`:**

| Field | Contents |
|---|---|
| `id`, `type`, `severity` | `low`, `medium`, `high` or `critical` |
| `status` | `new`, `acknowledged` or `resolved` |
| `dedupe_key` | The alert's subject: type plus message SHA-256, or type plus campaign id |
| `active_key` | Equals `dedupe_key` while the alert is open; NULL once resolved. A unique index allows one open alert per key on SQLite and PostgreSQL. |
| `analysis_id`, `campaign_id` | What the alert is about |
| `risk_id` | The risk version that raised or escalated the alert (pinned) |
| `title` | System-written |
| `summary_json` | Identifiers, labels and scores only (see below) |
| `occurrence_count`, `created_at`, `updated_at`, `last_seen_at` | Counters and timestamps |
| `acknowledged_by` / `at`, `resolved_by` / `at`, `resolution_note` | Analyst actions |
| `delivery_json` | E-mail status |
| `version` | Optimistic concurrency |

**`alert_event`:**

- Append-only history: action, actor, note, from and to state, a small detail object, timestamp.
- `analysis_id` is copied from the alert, so that retention delete mode removes the history with the
  alert.

**`summary_json` holds only:**

- analysis id(s);
- combined level and score;
- rule verdict label;
- ML class label and status;
- floors fired;
- conflict flag;
- pinned risk version;
- campaign id, label, confidence and member counts.

It **never** holds message subject, body, recipients, sender addresses or display names. Tests assert this
with distinctive fixture strings, across alerts, events, audit details and e-mails.

**Migration:** step 9 `alert_tables` (additive, idempotent). It runs at start-up and from every CLI path.

## 2. Rules

| Type | Raised when | Severity | Default |
|---|---|---|---|
| `high_risk_analysis` | Combined level ≥ `ALERT_MIN_LEVEL` | From the level: high → high, critical → critical | On; minimum `high` |
| `hard_evidence_floor` | A P5h hard-evidence floor fired **and** the level is below the minimum, so it never duplicates `high_risk_analysis` | From the level, at least medium | On (`ALERT_FLOOR_ENABLED`) |
| `review_conflict` | The combined assessment flags a rules-vs-ML conflict | low | On (`ALERT_CONFLICT_ENABLED`) |
| `new_campaign` | A candidate campaign with confidence ≥ `ALERT_CAMPAIGN_MIN_CONFIDENCE` exists without an alert | medium, or high for a high-confidence campaign | On; minimum `medium` |
| `campaign_growth` | An alerted campaign gained ≥ `ALERT_CAMPAIGN_GROWTH_MIN_NEW` members since the last alert/update, and `ALERT_CAMPAIGN_GROWTH_DEBOUNCE_MINUTES` have passed | medium | On; +1 member, 60 min |

With the default minimum of `high`, `hard_evidence_floor` does not fire, because every floor already lifts
the level to high. It becomes relevant when `ALERT_MIN_LEVEL=critical`.

`ALERTS_ENABLED=0` switches all alerting off.

**Triggers.** Every trigger is failure-isolated. An error is logged and audited as `alert_engine_error`, and
it never alters the upload, assessment, risk result or recompute.

- **Upload:** analysis alerts, then campaign alerts.
- **Threat-intel run and AI assessment:** analysis alerts, via the P5h risk hook.
- **`POST /analyses/{id}/risk/recompute`:** analysis alerts.
- **`POST /correlation/rebuild` and `rebuild-correlation`:** campaign alerts.
- **`backfill-risk`:** **no alerts unless `--alerts` is given**, so a backfill never creates an alert storm.

## 3. Dedupe and lifecycle

There is one open alert per `(type, subject)`. The subject is the message SHA-256 for analysis alerts and
the campaign id for campaign alerts.

| Situation | Result |
|---|---|
| No alert for the key yet | New alert (`new`), history `raised`, audit `alert_raised` |
| Identical re-upload (same SHA-256), alert open | `occurrence_count` +1, `last_seen_at` updated, history `occurrence`. No new alert and no e-mail. |
| Recompute raises the severity, alert `new` | Severity, summary and pinned `risk_id` updated, history `escalated`, audit `alert_escalated`, one e-mail |
| Recompute raises the severity, alert `acknowledged` | As above, **and reopened to `new`** (acknowledgement cleared) |
| Recompute lowers the level | **Never auto-resolves.** One history note `level_lowered` per change of level; severity unchanged. |
| Alert `resolved`, later result at the same or a lower level | Nothing |
| Alert `resolved`, later result **above the level at resolution** | A **new** alert (history `supersedes` → previous id) |
| Campaign grows within the debounce window | Nothing yet; picked up by a later pass |
| Campaign keeps growing | The one open growth alert counts occurrences; there are never several |

### Analyst transitions

Transitions are allowed for analyst and admin.

| Action | From | To | Notes |
|---|---|---|---|
| `acknowledge` | `new` | `acknowledged` | Optional note |
| `resolve` | `new`, `acknowledged` | `resolved` | **Note required**, at most 1,000 characters |
| `reopen` | `acknowledged`, `resolved` | `new` | 409 `ACTIVE_ALERT_EXISTS` if a newer open alert holds the key |

Transitions are concurrency-safe:

- They use a conditional `UPDATE … WHERE id AND version AND status IN (…)`.
- A lost race or stale `version` returns 409 `CONFLICT`. An invalid transition returns 409
  `INVALID_TRANSITION`.
- Each transition writes an `alert_event` and an audit event (`alert_acknowledged`, `alert_resolved` or
  `alert_reopened`) carrying the actor. The audit event records only the note's length, not its text.

## 4. API

Every route is in the central permission map, and anonymous requests get 401.

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/v1/alerts` | `alert:read` (viewer+) | Filters `status` (`new`, `acknowledged`, `resolved`, `open`), `severity`, `type`, `analysis_id`, `campaign_id`, `date_from`, `date_to`; `page`, `page_size` ≤ 100; newest first |
| GET | `/api/v1/alerts/summary` | `alert:read` | Counts by status and severity; `new` feeds the top-bar badge |
| GET | `/api/v1/alerts/{id}` | `alert:read` | With history; marks redacted analyses |
| POST | `/api/v1/alerts/{id}/acknowledge` | `alert:manage` (analyst+) | Body `{note?, version?}` |
| POST | `/api/v1/alerts/{id}/resolve` | `alert:manage` | Body `{note, version?}` |
| POST | `/api/v1/alerts/{id}/reopen` | `alert:manage` | Body `{version?}` |
| GET | `/api/v1/admin/alerts/config` | `config:status` (admin) | Effective configuration. The password is never returned and the username only as set/not set. |

## 5. Optional e-mail notification

E-mail is **OFF by default** (`ALERT_EMAIL_ENABLED=0`). The demo forces it off.

| Variable | Default | Meaning |
|---|---|---|
| `ALERT_EMAIL_ENABLED` | `0` | Master switch |
| `ALERT_EMAIL_MIN_SEVERITY` | `high` | Only alerts at or above this severity are e-mailed |
| `ALERT_SMTP_HOST` / `ALERT_SMTP_PORT` | — / `587` | SMTP server |
| `ALERT_SMTP_SECURITY` | `starttls` | `starttls`, `ssl` or `none`. TLS verification is always on (`ssl.create_default_context`, TLS 1.2 or later). |
| `ALERT_SMTP_USERNAME` / `ALERT_SMTP_PASSWORD` | empty | From the environment only. Never logged, stored, audited or returned. |
| `ALERT_EMAIL_FROM` / `ALERT_EMAIL_TO` | empty | The sender and a comma-separated recipient list. The **only** recipients ever used. |
| `ALERT_EMAIL_MAX_PER_MINUTE` | `10` | In-process rate limit; excess is recorded as `rate_limited` |
| `ALERT_SMTP_TIMEOUT_SECONDS` | `10` | Socket timeout |
| `APP_BASE_URL` | empty | For the link (`…/#alerts/{id}`) |

**Content** is limited to:

- alert id, type, severity and status;
- analysis id **or** campaign label (with confidence and member count);
- combined level and score, rule verdict label, ML class label, floors fired;
- a link to the alert;
- the standard disclaimer.

**No** message subject, body, recipients, addresses, domains or IPs.

**Templates and sending:**

- Templates are `backend/app/alerts/templates/alert_email.txt.j2` and `.html.j2`: Jinja2 3.1.6, pinned,
  with autoescape on.
- Messages are built with the stdlib `email` package and sent with `smtplib`.
- Headers contain only system values. Any CR, LF or NUL is rejected (`UnsafeHeader`), so header injection
  through configuration fails safely as `failed: message could not be built`.

**When mail is sent:**

- Sending runs **outside the request path**, in a daemon thread with a socket timeout and one retry.
- E-mail goes out only on a state change: raised, escalated or reopened. At most one e-mail per alert per
  state change, and never for an occurrence increment.
- `delivery_json.email.status` is one of `disabled`, `not_configured`, `below_threshold`, `rate_limited`,
  `queued`, `sent` or `failed`.
- A failure records a safe reason (the exception class only). `sent`, `failed` and `rate_limited` are
  audited.
- An SMTP outage never affects uploads or alert creation.

## 6. Retention (P5e)

- **Delete mode** removes the alerts and alert history tied to a deleted analysis. Both tables carry
  `analysis_id`, so they are in the generic dependents list and no orphans remain.
- **Redact mode** keeps alerts (they hold no personal data). The alert view marks the analysis as
  redacted.
- Legal holds are unaffected. Audit events, including alert events in the audit log, are never purged.
- Campaign alerts are not tied to one analysis and are kept.

## 7. Frontend

- **Top bar:** an `ALERTS n` badge counting **new** alerts. It polls `/alerts/summary` every 45 seconds,
  only while the tab is visible, and shows `—` if the count can't be fetched.
- **Alerts page** (all roles; actions for analysts):
  - the honesty strip and a stat strip;
  - filters and server pagination;
  - a detail panel with the pinned risk version, history, acknowledge, resolve (with a required note in a
    confirmation dialog) and reopen;
  - for admins, the read-only configuration.
- **Overview:** an "Open alerts" panel.
- **Analysis page:** a compact open-alert banner.

## 8. Limitations

- No real-time mailbox monitoring: R36 (IMAP or Graph ingestion) is not implemented.
- E-mail rate limiting and the background sender are in-process. With several worker processes, each has
  its own limit.
- A campaign growth pass runs only when an upload or rebuild happens, so the debounce window is a minimum
  delay, not a schedule.
- Alerts follow the combined risk index (P5h) and inherit its caveats. It is an index, not a probability,
  and its thresholds were derived on old, partly synthetic data.
