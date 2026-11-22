"""Generate the code-derived tables in docs/ARCHITECTURE.md from the running code.

    cd backend && APP_ENV=test python scripts/gen_doc_tables.py          # rewrite the generated blocks
    cd backend && APP_ENV=test python scripts/gen_doc_tables.py --check  # exit 1 if they are stale

Blocks (between ``<!-- gen:NAME:begin -->`` and ``<!-- gen:NAME:end -->``):

* ``routes``      every served route with its permission and the least-privileged role holding it, from
                  ``app.security.permissions.ROUTE_PERMISSIONS`` and the FastAPI route inventory;
* ``roles``       the role → permission map;
* ``tables``      the SQLAlchemy tables;
* ``migrations``  the versioned migration steps in ``app.core.migrations.STEPS``.

API documentation routes (registered only in dev/test) are listed with that note.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

os.environ.setdefault("APP_ENV", "test")
BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
DOC = BACKEND.parent / "docs" / "ARCHITECTURE.md"


def blocks() -> dict[str, str]:
    from fastapi.routing import iter_route_contexts

    import app.core.models  # noqa: F401  (registers the tables)
    from app.core.db import Base
    from app.core.migrations import STEPS
    from app.main import create_app
    from app.security.permissions import PUBLIC, ROLE_PERMISSIONS, ROLES, ROUTE_PERMISSIONS, SELF, lowest_role_for

    fa = create_app()
    served = set()
    for rc in iter_route_contexts(fa.routes):
        path = getattr(rc, "path_format", None) or rc.path
        for m in rc.methods or ():
            if m != "HEAD":
                served.add((m, path))
    out: dict[str, str] = {}

    lines = ["| Method | Path | Permission | Lowest role |", "|---|---|---|---|"]
    for m, p in sorted(served, key=lambda r: (r[1], r[0])):
        perm = ROUTE_PERMISSIONS.get((m, p), "UNMAPPED (denied)")
        if perm == PUBLIC:
            role = "anonymous"
        elif perm == SELF:
            role = "any signed-in user"
        else:
            role = lowest_role_for(perm) or "none"
        note = " (dev/test only)" if p in ("/openapi.json", "/docs", "/redoc") else ""
        lines.append(f"| {m} | `{p}`{note} | `{perm}` | {role} |")
    lines.append("")
    lines.append(f"{len(served)} routes. A route missing from the map is denied to everyone; "
                 "`tests/unit/test_access_control.py` fails if one is added without a permission.")
    out["routes"] = "\n".join(lines)

    lines = ["| Role | Permissions added at this role |", "|---|---|"]
    prev: frozenset[str] = frozenset()
    for role in ROLES:
        perms = ROLE_PERMISSIONS[role]
        added = sorted(perms - prev - {SELF})
        lines.append(f"| {role} | " + ", ".join(f"`{x}`" for x in added) + " |")
        prev = perms
    lines.append("")
    lines.append("Roles are cumulative (analyst includes viewer, admin includes analyst) and global: "
                 "there are no per-case ACLs.")
    out["roles"] = "\n".join(lines)

    lines = ["| Table | Columns |", "|---|---:|"]
    for name, t in sorted(Base.metadata.tables.items()):
        lines.append(f"| `{name}` | {len(t.columns)} |")
    lines.append("")
    lines.append(f"{len(Base.metadata.tables)} tables (SQLAlchemy models in `backend/app/core/models.py`).")
    out["tables"] = "\n".join(lines)

    lines = ["| Version | Step |", "|---:|---|"]
    for version, name, _fn in STEPS:
        lines.append(f"| {version} | `{name}` |")
    out["migrations"] = "\n".join(lines)
    return out


def main() -> int:
    check = "--check" in sys.argv
    text = DOC.read_text(encoding="utf-8")
    new = text
    for name, body in blocks().items():
        b, e = f"<!-- gen:{name}:begin -->", f"<!-- gen:{name}:end -->"
        if b not in new or e not in new:
            print(f"markers for {name!r} missing in {DOC}", file=sys.stderr)
            return 1
        new = re.sub(re.escape(b) + r".*?" + re.escape(e), lambda _m, b=b, e=e, body=body: f"{b}\n{body}\n{e}",
                     new, flags=re.S)
    if check:
        if new != text:
            print("docs/ARCHITECTURE.md generated tables are stale: run backend/scripts/gen_doc_tables.py",
                  file=sys.stderr)
            return 1
        print("docs/ARCHITECTURE.md generated tables are current")
        return 0
    DOC.write_text(new, encoding="utf-8")
    print(f"wrote generated tables into {DOC.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
