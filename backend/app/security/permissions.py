"""Central role → permission map and route → permission map (deny by default).

Every route the app serves must appear in ``ROUTE_PERMISSIONS``. A route that
is missing is denied to everyone (401 anonymous, 403 authenticated), and the
route-inventory test fails, so a new endpoint is protected by default.
"""
from __future__ import annotations

PUBLIC = "public"
SELF = "self"                  # any authenticated user acting on their own account

VIEWER, ANALYST, ADMIN = "viewer", "analyst", "admin"
ROLES = (VIEWER, ANALYST, ADMIN)

_VIEWER_PERMS = {
    SELF, "analysis:read", "case:read", "report:download", "intel:read", "assessment:read", "ml:status",
    "correlation:read", "search:read", "attack:read",
    "risk:read",       # P5h: combined risk assessment (masked per P5e like every response)
}
_ANALYST_PERMS = _VIEWER_PERMS | {
    "analysis:create", "case:write", "evidence:verify", "intel:run", "assessment:run", "ml:run",
    "attack:recompute",
    "pii:view",        # P5e: unmasked sender/recipient addresses, display names and body text
    "custody:read",    # P5e: per-analysis audit timeline
    "risk:recompute",  # P5h
}
_ADMIN_PERMS = _ANALYST_PERMS | {"users:manage", "config:status", "docs:read", "correlation:rebuild",
                                 "audit:read", "audit:manage", "retention:manage"}   # P5e

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    VIEWER: frozenset(_VIEWER_PERMS),
    ANALYST: frozenset(_ANALYST_PERMS),
    ADMIN: frozenset(_ADMIN_PERMS),
}

V1 = "/api/v1"

# (METHOD, path template) → permission. HEAD is treated as GET.
ROUTE_PERMISSIONS: dict[tuple[str, str], str] = {
    # public allowlist — keep this list minimal
    ("GET", f"{V1}/health"): PUBLIC,
    # P5i readiness probe for container health checks: anonymous, returns only {"status": ...}
    ("GET", f"{V1}/health/ready"): PUBLIC,
    ("POST", f"{V1}/auth/login"): PUBLIC,
    # own account
    ("GET", f"{V1}/auth/me"): SELF,
    ("POST", f"{V1}/auth/logout"): SELF,
    ("POST", f"{V1}/auth/change-password"): SELF,
    # analyses
    ("POST", f"{V1}/analyses"): "analysis:create",
    ("GET", f"{V1}/analyses"): "analysis:read",
    ("GET", f"{V1}/analyses/{{analysis_id}}"): "analysis:read",
    # investigations, evidence, reports
    ("POST", f"{V1}/investigations/from-analysis/{{analysis_id}}"): "case:write",
    ("GET", f"{V1}/investigations"): "case:read",
    ("GET", f"{V1}/investigations/{{case_id}}"): "case:read",
    ("POST", f"{V1}/investigations/{{case_id}}/evidence-integrity/{{analysis_id}}"): "evidence:verify",
    ("GET", f"{V1}/investigations/{{case_id}}/report/{{analysis_id}}"): "report:download",
    # ML
    ("GET", f"{V1}/ml/status"): "ml:status",
    ("POST", f"{V1}/ml/classify"): "ml:run",
    ("POST", f"{V1}/ml/explain"): "ml:run",
    # AI assessments (ML + SHAP + Mistral)
    ("GET", f"{V1}/analyses/{{analysis_id}}/assessment"): "assessment:read",
    ("GET", f"{V1}/analyses/{{analysis_id}}/assessments"): "assessment:read",
    ("GET", f"{V1}/analyses/{{analysis_id}}/assessments/{{assessment_id}}"): "assessment:read",
    ("POST", f"{V1}/llm/forensic-summary"): "assessment:run",
    ("POST", f"{V1}/analyses/{{analysis_id}}/forensic-summary"): "assessment:run",
    ("GET", f"{V1}/llm/status"): "config:status",
    # threat intel
    ("GET", f"{V1}/intel/status"): "config:status",
    ("POST", f"{V1}/analyses/{{analysis_id}}/threat-intel"): "intel:run",
    ("GET", f"{V1}/analyses/{{analysis_id}}/threat-intel"): "intel:read",
    # case membership (P5c)
    ("GET", f"{V1}/investigations/{{case_id}}/analyses"): "case:read",
    ("POST", f"{V1}/investigations/{{case_id}}/analyses"): "case:write",
    ("DELETE", f"{V1}/investigations/{{case_id}}/analyses/{{analysis_id}}"): "case:write",
    ("GET", f"{V1}/investigations/{{case_id}}/indicators"): "case:read",
    # correlation, campaigns, graph, search (P5c)
    ("GET", f"{V1}/analyses/{{analysis_id}}/correlation"): "correlation:read",
    ("GET", f"{V1}/campaigns"): "correlation:read",
    ("GET", f"{V1}/campaigns/{{campaign_id}}"): "correlation:read",
    ("GET", f"{V1}/graph/entities/{{entity_type}}/{{value}}"): "correlation:read",
    ("GET", f"{V1}/search"): "search:read",
    ("POST", f"{V1}/correlation/rebuild"): "correlation:rebuild",
    # MITRE ATT&CK mapping + source-type hypotheses (P5d)
    ("GET", f"{V1}/analyses/{{analysis_id}}/attack"): "attack:read",
    # P5g: infrastructure geolocation (stored data only), analytics and system info (all signed-in roles)
    ("GET", f"{V1}/analyses/{{analysis_id}}/geo"): "analysis:read",
    ("GET", f"{V1}/campaigns/{{campaign_id}}/geo"): "correlation:read",
    ("GET", f"{V1}/analytics/summary"): "analysis:read",
    # P5e: tamper-evident audit log, custody, retention, legal holds, erasure
    ("GET", f"{V1}/audit/events"): "audit:read",
    ("GET", f"{V1}/audit/export"): "audit:read",
    ("GET", f"{V1}/audit/verify"): "audit:read",
    ("GET", f"{V1}/audit/checkpoint"): "audit:read",
    ("POST", f"{V1}/audit/checkpoint"): "audit:manage",
    ("GET", f"{V1}/analyses/{{analysis_id}}/custody"): "custody:read",
    ("GET", f"{V1}/admin/retention/status"): "retention:manage",
    ("POST", f"{V1}/admin/retention/run"): "retention:manage",
    ("GET", f"{V1}/admin/holds"): "retention:manage",
    ("POST", f"{V1}/admin/holds"): "retention:manage",
    ("POST", f"{V1}/admin/holds/{{hold_id}}/clear"): "retention:manage",
    ("DELETE", f"{V1}/admin/analyses/{{analysis_id}}"): "retention:manage",
    ("GET", f"{V1}/system/info"): "analysis:read",
    ("GET", f"{V1}/analyses/{{analysis_id}}/attack/history"): "attack:read",
    ("POST", f"{V1}/analyses/{{analysis_id}}/attack/recompute"): "attack:recompute",
    ("GET", f"{V1}/analyses/{{analysis_id}}/risk"): "risk:read",                 # P5h
    ("GET", f"{V1}/analyses/{{analysis_id}}/risk/history"): "risk:read",
    ("POST", f"{V1}/analyses/{{analysis_id}}/risk/recompute"): "risk:recompute",
    # user administration
    ("GET", f"{V1}/admin/users"): "users:manage",
    ("POST", f"{V1}/admin/users"): "users:manage",
    ("PATCH", f"{V1}/admin/users/{{user_id}}"): "users:manage",
    ("POST", f"{V1}/admin/users/{{user_id}}/reset-password"): "users:manage",
    # API documentation (registered only in dev/test; absent elsewhere)
    ("GET", "/openapi.json"): "docs:read",
    ("GET", "/docs"): "docs:read",
    ("GET", "/redoc"): "docs:read",
}


def role_allows(role: str | None, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role or "", frozenset())


def lowest_role_for(permission: str) -> str | None:
    """The least-privileged role holding a permission (for docs); PUBLIC → None."""
    for role in ROLES:
        if role_allows(role, permission):
            return role
    return None
