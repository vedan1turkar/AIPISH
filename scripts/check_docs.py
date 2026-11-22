#!/usr/bin/env python3
"""Check documentation links, referenced paths and environment variables.

For every tracked Markdown file (README.md, top-level *.md, docs/**, data/*.md):

1. relative Markdown links ``[text](path#anchor)`` must point to a file or directory in the repository;
2. backtick-quoted repository paths (``backend/...``, ``frontend/...``, ``docs/...``, ``scripts/...``,
   ``deploy/...``, ``data/...``, ``.github/...``) must exist, unless they are gitignored local-only paths
   listed in LOCAL_ONLY;
3. backtick-quoted environment variables with a known project prefix must appear in an env template
   (``.env.example`` or ``deploy/env.example``) or in NON_TEMPLATE_VARS (test, CI or tooling variables,
   each with a reason) AND must be referenced somewhere in code/config, so docs cannot describe a
   variable that does not exist.

Historical sections (``docs/CHANGELOG.md`` and the "Changes made in ..." history in the matrix) describe
past states, so only their links are checked.

Exit status 1 on any error. Standard library only; uses ``git ls-files`` for the file list.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PREFIXES = ("APP_", "AIPISH_", "INTEL_", "ENRICH_", "ALERT_", "ALERTS_", "RETENTION_", "CASE_EVIDENCE_",
            "PARSER_", "OLLAMA_", "LLM_", "NGINX_", "POSTGRES_", "VIRUSTOTAL_", "ABUSEIPDB_", "SHODAN_",
            "IPINFO_", "MAXMIND_", "DATABASE_URL", "TEST_DATABASE_URL", "VITE_")

# Variables that are deliberately not in an env template: name -> reason.
NON_TEMPLATE_VARS = {
    "TEST_DATABASE_URL": "test-only: points the pytest suite at a throwaway PostgreSQL",
    "AIPISH_RUN_LIVE": "test-only: opt-in live provider/LLM tests",
    "APP_ENV_FILE": "tooling: alternative .env path for the config loader",
    "INTEL_REQUEST_LOG": "debug-only: redacted outbound request log, off by default",
    "AIPISH_NEW_USER_PASSWORD": "CLI-only: non-interactive password for create-user",
    "VITE_API_BASE": "frontend build-time variable",
    "AIPISH_SMOKE_BASE": "smoke-test script input",
    "AIPISH_SMOKE_COMPOSE": "smoke-test script input",
    "AIPISH_DEMO_PORT": "demo script input (scripts/demo-up.sh)",
    "AIPISH_DEMO_PROJECT": "demo script input (scripts/demo-up.sh)",
    "AIPISH_RUN_INTEGRATION": "test-only: opt-in integration tests",
    "OLLAMA_HOST": "Ollama's own server setting on the host, not read by AIPISH",
}

# Upper-case tokens with a project prefix that are not environment variables (API error codes).
NOT_ENV = {"INTEL_IN_PROGRESS", "INTEL_NOT_RUN", "INTEL_RUN_NOT_FOUND"}

# Gitignored, local-only paths that docs may mention.
LOCAL_ONLY = (".env", "deploy/.env", ".demo/", "backend/.dev_credentials", "backend/db/", "models/",
              "data/raw/", "data/processed/", "backend/.venv", "frontend/node_modules", "frontend/dist")

PATH_ROOTS = ("backend/", "frontend/", "docs/", "scripts/", "deploy/", "data/", ".github/")
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
IMG_RE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)")
TICK_RE = re.compile(r"`([^`\n]+)`")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*[A-Z0-9]$")


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    return [p for p in out.splitlines() if (ROOT / p).exists()]


def env_templates() -> set[str]:
    names = set()
    for t in (".env.example", "deploy/env.example"):
        for ln in (ROOT / t).read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\s*#?\s*([A-Z][A-Z0-9_]+)=", ln)
            if m:
                names.add(m.group(1))
    return names


def code_corpus(files: list[str]) -> str:
    keep = (".py", ".ts", ".tsx", ".sh", ".yml", ".yaml", ".conf", ".template", ".toml", ".cfg", ".ini",
            ".example", "Makefile", "Dockerfile", ".js", ".mjs", ".json")
    parts = []
    for f in files:
        if f.endswith(".md") or not f.endswith(keep) or "__fixtures__" in f or "/fixtures/" in f:
            continue
        try:
            parts.append((ROOT / f).read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass
    return "\n".join(parts)


def is_local_only(p: str) -> bool:
    return any(p == lo.rstrip("/") or p.startswith(lo) for lo in LOCAL_ONLY)


def main() -> int:
    files = tracked()
    fileset = set(files)
    dirs = {str(Path(f).parent) for f in files} | {"."}
    for f in list(dirs):
        parts = Path(f).parts
        dirs |= {str(Path(*parts[:i])) for i in range(1, len(parts))}
    docs = [f for f in files if f.endswith(".md") and (f.count("/") == 0 or f.startswith(("docs/", "data/")))]
    templates = env_templates()
    corpus = code_corpus(files)
    errors: list[str] = []

    def exists(rel: str) -> bool:
        rel = rel.rstrip("/")
        return rel in fileset or rel in dirs or (ROOT / rel).exists() and not is_local_only(rel)

    for doc in docs:
        text = (ROOT / doc).read_text(encoding="utf-8")
        history = doc == "docs/CHANGELOG.md"
        if doc == "docs/requirements-matrix.md":
            # Only the current sections are checked for paths/env vars; the history is past state.
            cut = text.find("## Changes made in")
            current = text[:cut] + text[text.find("## Matrix"):] if cut != -1 else text
        else:
            current = text
        base = (ROOT / doc).parent
        # 1. links
        for target in LINK_RE.findall(text) + IMG_RE.findall(text):
            if re.match(r"^(https?:|mailto:|#)", target):
                continue
            path = target.split("#", 1)[0].split("?", 1)[0]
            if not path:
                continue
            rel = (base / path).resolve()
            try:
                rel_s = str(rel.relative_to(ROOT))
            except ValueError:
                errors.append(f"{doc}: link outside repo: {target}")
                continue
            if not exists(rel_s):
                errors.append(f"{doc}: broken link: {target}")
        if history:
            continue
        # 2 + 3. backtick paths and env vars (skip fenced code blocks for paths? keep: commands use real paths)
        for tok in TICK_RE.findall(current):
            tok = tok.strip()
            for cand in re.findall(r"[A-Za-z0-9_./*-]+", tok):
                if cand.startswith(PATH_ROOTS) and "*" not in cand and "{" not in tok:
                    p = cand.rstrip(".,;:)")
                    p = re.sub(r":\d+$", "", p)
                    if "..." in p or is_local_only(p):
                        continue
                    if not exists(p):
                        errors.append(f"{doc}: referenced path does not exist: {p}")
            name = tok.split("=", 1)[0].strip()
            if ENV_RE.match(name) and name.startswith(PREFIXES) and "_" in name and name not in NOT_ENV:
                in_tpl = name in templates or name in NON_TEMPLATE_VARS
                in_code = re.search(r"\b" + re.escape(name) + r"\b", corpus) is not None
                if not in_tpl:
                    errors.append(f"{doc}: env var {name} is not in .env.example or deploy/env.example")
                if not in_code and name not in NON_TEMPLATE_VARS:
                    errors.append(f"{doc}: env var {name} is not referenced by any code or config")

    for e in sorted(set(errors)):
        print("ERROR: " + e)
    print(f"checked {len(docs)} Markdown files: {len(set(errors))} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
