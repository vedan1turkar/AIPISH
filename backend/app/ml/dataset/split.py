"""Leakage-safe grouping and class-stratified train/validation/test assignment.

HARD groups (union-find; a group never spans two splits). Messages are linked
when they share:
  1. a near-duplicate cluster (SimHash, see dedup.py) - same text/template;
  2. a thread (Message-ID / In-Reply-To / References) - quoted conversation;
  3. a campaign key: same target label + same canonical subject
     (>= 12 chars, not generic);
  4. a synthetic template id (all samples of one template stay together).

SENDER constraint (soft + audited). The sender key is the sender domain, or
the hashed sender address when the domain is shared (free-mail, or more than
SHARED_DOMAIN_FRACTION of the corpus, e.g. enron.com). Making senders a hard
link chained most of each real class into one component (mailing-list threads
join posters, forged brand senders join phishing campaigns), which would make
a representative validation/test set impossible. Instead:
  - same-sender groups are merged up to SENDER_MERGE_CAP messages;
  - assignment prefers the split that already holds a group's sender keys
    (affinity), which keeps most same-sender mail together;
  - the residual overlap is measured and reported;
  - every validation/test message whose sender key also occurs in train is
    flagged `sender_seen_in_train`; the complementary `sender-disjoint`
    subset gives a strict evaluation with zero sender overlap.
Synthetic senders are random fill-ins, so synthetic samples group by template.
"""
from __future__ import annotations

import hashlib
from collections import Counter, defaultdict

from app.ml.dataset.dedup import UnionFind
from app.ml.dataset.labels import LABELS

SPLITS: tuple[str, ...] = ("train", "validation", "test")
SPLIT_FRACTIONS: dict[str, float] = {"train": 0.70, "validation": 0.15, "test": 0.15}
SHARED_DOMAIN_FRACTION = 0.05
MIN_CAMPAIGN_SUBJECT_LEN = 12
FREEMAIL = frozenset({
    "aol.com", "gmail.com", "hotmail.com", "msn.com", "yahoo.com", "yahoo.co.uk",
    "outlook.com", "live.com", "excite.com", "earthlink.net", "netscape.net",
    "mail.com", "comcast.net", "juno.com", "lycos.com", "usa.net", "aim.com",
    # synthetic stand-ins for free-mail / bulk hosts (see synthetic.py)
    "freemail.example", "mailhost.example",
})
GENERIC_SUBJECTS = frozenset({
    "", "(no subject)", "no subject", "hi", "hello", "fyi", "meeting", "update", "test",
    "thanks", "thank you", "question", "important", "urgent",
})
HARD_KINDS = ("near_dup_cluster", "thread", "campaign_subject", "synthetic_template")
# Placeholder domains written by corpus sanitisation; not a real sender identity.
SANITISED_SENDER_DOMAINS = frozenset({"spamassassin.taint.org"})
# Same-sender hard groups are merged while the merged group stays <= this size.
SENDER_MERGE_CAP = 150


def shared_domains(records: list[dict]) -> set[str]:
    counts = Counter(r["from_domain"] for r in records if r["from_domain"])
    limit = SHARED_DOMAIN_FRACTION * len(records)
    return set(FREEMAIL) | {d for d, n in counts.items() if n > limit}


def sender_key(r: dict, shared: set[str]) -> str | None:
    if r["is_synthetic"] or r["from_domain"] in SANITISED_SENDER_DOMAINS:
        return None
    if r["from_domain"] and r["from_domain"] not in shared:
        return "dom:" + r["from_domain"]
    if r["from_address_sha256"]:
        return "addr:" + r["from_address_sha256"]
    return None


def hard_keys(r: dict) -> dict[str, list[str]]:
    keys = {
        "near_dup_cluster": ["dup:" + r["near_dup_cluster"]],
        "thread": ["msg:" + m for m in ([r["message_id"]] if r["message_id"] else []) + r["thread_refs"]],
        "campaign_subject": [],
        "synthetic_template": [],
    }
    if r.get("synthetic_template"):
        keys["synthetic_template"] = ["tpl:" + r["synthetic_template"]]
        return keys
    subj = r["subject_canonical"]
    if len(subj) >= MIN_CAMPAIGN_SUBJECT_LEN and subj not in GENERIC_SUBJECTS:
        keys["campaign_subject"] = [f"subj:{r['label']}:{subj}"]
    return keys


def assign_groups(records: list[dict]) -> dict[str, str]:
    """Return id -> group id (sha256 of the sorted member ids, 16 hex).

    Pass 1 joins hard keys without limit. Pass 2 additionally merges groups
    that share a sender key, but only while the merged group stays within
    SENDER_MERGE_CAP, so small senders (an Enron custodian, a mailing list)
    stay whole without chaining the corpus into one component.
    """
    uf = UnionFind()
    first: dict[str, str] = {}
    for r in records:
        uf.find(r["id"])
        for ks in hard_keys(r).values():
            for k in ks:
                if k in first:
                    uf.union(r["id"], first[k])
                else:
                    first[k] = r["id"]
    size = Counter(uf.find(r["id"]) for r in records)
    shared = shared_domains(records)
    by_sender: dict[str, list[str]] = defaultdict(list)
    for r in records:
        if (k := sender_key(r, shared)):
            by_sender[k].append(r["id"])
    for k in sorted(by_sender, key=lambda k: (len(by_sender[k]), k)):
        ids = by_sender[k]
        for rid in ids[1:]:
            a, b = uf.find(ids[0]), uf.find(rid)
            if a != b and size[a] + size[b] <= SENDER_MERGE_CAP:
                uf.union(a, b)
                size[uf.find(a)] = size[a] + size[b]
    members: dict[str, list[str]] = defaultdict(list)
    for r in records:
        members[uf.find(r["id"])].append(r["id"])
    gid = {root: hashlib.sha256("\n".join(sorted(m)).encode()).hexdigest()[:16]
           for root, m in members.items()}
    return {r["id"]: gid[uf.find(r["id"])] for r in records}


def assign_splits(records: list[dict]) -> dict[str, str]:
    """Greedy, deterministic, class-stratified assignment of whole groups.

    Groups are placed largest first. Among splits that still need the group's
    classes (positive deficit), the one already holding most of the group's
    sender keys wins; ties and the no-room case fall back to the largest
    class-weighted deficit.
    """
    shared = shared_domains(records)
    mix: dict[str, Counter] = defaultdict(Counter)
    senders: dict[str, set[str]] = defaultdict(set)
    for r in records:
        mix[r["group_id"]][r["label"]] += 1
        if (k := sender_key(r, shared)):
            senders[r["group_id"]].add(k)
    totals = Counter(r["label"] for r in records)
    current = {s: Counter() for s in SPLITS}
    held: dict[str, set[str]] = {s: set() for s in SPLITS}
    order = sorted(mix, key=lambda g: (-sum(mix[g].values()), g))
    group_split: dict[str, str] = {}
    for g in order:
        m = mix[g]

        def deficit(s: str) -> float:
            return sum(n * (SPLIT_FRACTIONS[s] * totals[lbl] - current[s][lbl]) / totals[lbl]
                       for lbl, n in m.items())

        room = [s for s in SPLITS if deficit(s) > 0]
        if room:
            best = max(room, key=lambda s: (len(senders[g] & held[s]), deficit(s), -SPLITS.index(s)))
        else:
            best = max(SPLITS, key=lambda s: (deficit(s), -SPLITS.index(s)))
        group_split[g] = best
        current[best].update(m)
        held[best] |= senders[g]
    return {r["id"]: group_split[r["group_id"]] for r in records}


def flag_sender_seen(records: list[dict]) -> None:
    """Set r['sender_seen_in_train'] (always False for train records)."""
    shared = shared_domains(records)
    train_keys = {k for r in records if r["split"] == "train" and (k := sender_key(r, shared))}
    for r in records:
        k = sender_key(r, shared)
        r["sender_seen_in_train"] = r["split"] != "train" and k is not None and k in train_keys


def leakage_report(records: list[dict]) -> dict[str, int]:
    """Hard keys appearing in more than one split (all must be 0)."""
    seen: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for r in records:
        seen["group"][r["group_id"]].add(r["split"])
        seen["norm_sha256"][r["norm_sha256"]].add(r["split"])
        for kind, ks in hard_keys(r).items():
            for k in ks:
                seen[kind][k].add(r["split"])
    return {kind: sum(1 for v in seen[kind].values() if len(v) > 1)
            for kind in ("group", "norm_sha256", *HARD_KINDS)}


def sender_overlap_report(records: list[dict]) -> dict:
    """Residual (soft) sender overlap, for the data card."""
    shared = shared_domains(records)
    by_key: dict[str, set[str]] = defaultdict(set)
    for r in records:
        if (k := sender_key(r, shared)):
            by_key[k].add(r["split"])
    out: dict = {"sender_keys": len(by_key),
                 "sender_keys_in_multiple_splits": sum(1 for v in by_key.values() if len(v) > 1)}
    for s in ("validation", "test"):
        rows = [r for r in records if r["split"] == s]
        seen = sum(1 for r in rows if r["sender_seen_in_train"])
        out[s] = {"messages": len(rows), "sender_seen_in_train": seen,
                  "sender_disjoint": len(rows) - seen}
    return out


def split_counts(records: list[dict], subset: str | None = None) -> dict[str, dict[str, int]]:
    out = {s: {lbl: 0 for lbl in LABELS} for s in SPLITS}
    for r in records:
        if subset == "sender_disjoint" and r.get("sender_seen_in_train"):
            continue
        out[r["split"]][r["label"]] += 1
    return out
