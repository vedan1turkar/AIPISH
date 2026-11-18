"""Exact and near-duplicate detection (64-bit SimHash over word 3-shingles)."""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

SIMHASH_BITS = 64
NEAR_DUP_MAX_HAMMING = 6  # <= 6 of 64 bits differ; tuned for short e-mail bodies
_BANDS = 8                # pigeonhole: distance <= 6 => at least one 8-bit band equal
_TOKEN_RE = re.compile(r"<url>|<email>|[a-z0-9]+")  # quote markers (">") are not tokens
MIN_TOKENS_FOR_NEAR_DUP = 10  # shorter bodies are only checked for exact duplicates


def tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def simhash(text: str) -> int:
    toks = tokens(text)
    feats = [" ".join(toks[i:i + 3]) for i in range(max(1, len(toks) - 2))] if toks else [""]
    acc = [0] * SIMHASH_BITS
    for f in feats:
        h = int.from_bytes(hashlib.blake2b(f.encode(), digest_size=8).digest(), "big")
        for b in range(SIMHASH_BITS):
            acc[b] += 1 if (h >> b) & 1 else -1
    return sum(1 << b for b in range(SIMHASH_BITS) if acc[b] > 0)


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # deterministic: lexicographically smaller id becomes root
            if rb < ra:
                ra, rb = rb, ra
            self.parent[rb] = ra


def exact_duplicates(records: list[dict]) -> tuple[list[dict], list[dict]]:
    """Keep the first record per norm_sha256 (input order is deterministic).

    If the same normalised content carries different target labels, every
    copy is dropped (label conflict) rather than picking one.
    """
    by_hash: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_hash[r["norm_sha256"]].append(r)
    kept, removed = [], []
    for r in records:
        group = by_hash[r["norm_sha256"]]
        if len({g["label"] for g in group}) > 1:
            removed.append({**_ref(r), "reason": "exact_duplicate_label_conflict"})
        elif group[0] is r:
            kept.append(r)
        else:
            removed.append({**_ref(r), "reason": "exact_duplicate", "duplicate_of": group[0]["id"]})
    return kept, removed


def near_duplicate_clusters(records: list[dict]) -> dict[str, str]:
    """Return id -> cluster id (cluster id = smallest member id)."""
    uf = UnionFind()
    buckets: dict[tuple[int, int], list[tuple[int, str]]] = defaultdict(list)
    width = SIMHASH_BITS // _BANDS
    for r in records:
        uf.find(r["id"])
        if r["n_tokens"] < MIN_TOKENS_FOR_NEAR_DUP:
            continue
        for band in range(_BANDS):
            key = (band, (r["simhash"] >> (band * width)) & ((1 << width) - 1))
            buckets[key].append((r["simhash"], r["id"]))
    for members in buckets.values():
        reps: dict[int, str] = {}
        for sh, rid in members:
            for rsh, rrid in reps.items():
                if hamming(sh, rsh) <= NEAR_DUP_MAX_HAMMING:
                    uf.union(rid, rrid)
            reps.setdefault(sh, rid)
    return {r["id"]: uf.find(r["id"]) for r in records}


def _ref(r: dict) -> dict:
    return {"id": r["id"], "source": r["source"], "source_file": r["source_file"],
            "source_member": r["source_member"], "label": r["label"]}
