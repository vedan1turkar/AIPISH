"""Pinned ATT&CK technique catalog (only techniques the mapping rules can evidence)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

CATALOG_FILE = Path(__file__).with_name("data") / "techniques.json"
REQUIRED = ("technique_id", "name", "tactics", "url", "description")


@dataclass(frozen=True)
class Catalog:
    version: str
    attack_version: str
    verified: bool
    meta: dict
    techniques: tuple[dict, ...]

    def technique(self, tid: str) -> dict:
        for t in self.techniques:
            if t["technique_id"] == tid:
                return t
        raise KeyError(f"technique {tid} is not in the pinned catalog")

    @property
    def ids(self) -> set[str]:
        return {t["technique_id"] for t in self.techniques}


@lru_cache
def get_catalog() -> Catalog:
    raw = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
    techs = tuple(raw["techniques"])
    ids = [t["technique_id"] for t in techs]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate technique ids in catalog")
    for t in techs:
        missing = [k for k in REQUIRED if not t.get(k)]
        if missing:
            raise ValueError(f"catalog entry {t.get('technique_id')} missing {missing}")
    meta = raw["attack"]
    return Catalog(raw["catalog_version"], meta["version"], bool(meta.get("verified_against_official_data")),
                   meta, techs)
