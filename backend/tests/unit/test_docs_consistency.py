"""P5z: documentation cannot drift from the code or the requirements matrix.

* ``scripts/matrix_counts.py --check``: the Counts table and docs/REQUIREMENTS_SUMMARY.md match the
  R1-R60 Matrix table (each ID exactly once, known statuses only).
* ``scripts/check_docs.py``: relative links and referenced paths exist; documented environment variables are
  in an env template (or an explicit allowlist) and are referenced by code or config.
* ``backend/scripts/gen_doc_tables.py --check``: the route/permission, role, table and migration tables in
  docs/ARCHITECTURE.md match the running code.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, timeout=120)


def test_requirements_matrix_totals_are_consistent():
    r = _run("scripts/matrix_counts.py", "--check")
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(),
                    reason="needs a git checkout (uses git ls-files)")
def test_docs_links_paths_and_env_vars():
    r = _run("scripts/check_docs.py")
    assert r.returncode == 0, r.stdout + r.stderr


def test_architecture_generated_tables_are_current():
    sys.path.insert(0, str(ROOT / "backend" / "scripts"))
    try:
        import gen_doc_tables as g
    finally:
        sys.path.pop(0)
    text = g.DOC.read_text(encoding="utf-8")
    for name, body in g.blocks().items():
        block = f"<!-- gen:{name}:begin -->\n{body}\n<!-- gen:{name}:end -->"
        assert block in text, f"docs/ARCHITECTURE.md block {name!r} is stale: run backend/scripts/gen_doc_tables.py"
