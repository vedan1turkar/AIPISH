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
}
_ANALYST_PERMS = _VIEWER_PERMS | {
    "analysis:create", "case:write", "evidence:verify", "intel:run", "assessment:run", "ml:run",
}
_ADMIN_PERMS = _ANALYST_PERMS | {"users:manage", "config:status", "docs:read"}

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
