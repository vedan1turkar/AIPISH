"""Build the labelled corpus: normalise -> label -> dedup -> group -> split.

Usage: python -m app.ml.dataset.build [--data-dir DIR] [--no-real]

Outputs (data/):
  processed/emails.jsonl   full normalised records incl. text   (git-ignored)
  manifest/manifest.csv    one row per kept message, no text     (tracked)
  manifest/exclusions.csv  every dropped message and why         (tracked)
  manifest/stats.json      counts used by the data card          (tracked)
  DATA_CARD.md             generated count section refreshed     (tracked)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path

from app.ml.dataset import synthetic
from app.ml.dataset.acquire import DEFAULT_DATA_DIR
from app.ml.dataset.dedup import exact_duplicates, near_duplicate_clusters, simhash, tokens
from app.ml.dataset.labels import LABEL_MAP, LABELS, map_label
from app.ml.dataset.normalize import Excluded, RawMessage, normalize
from app.ml.dataset.split import (SPLIT_FRACTIONS, SPLITS, assign_groups, assign_splits,
                                  flag_sender_seen, leakage_report, sender_overlap_report,
                                  split_counts)

SOURCE_ORDER = ("nazario", "spamassassin", "enron", "synthetic")
MANIFEST_FIELDS = ("id", "split", "label", "source", "original_label", "is_synthetic",
                   "synthetic_template", "source_file", "source_member", "raw_sha256",
                   "norm_sha256", "simhash", "near_dup_cluster", "group_id", "sender_seen_in_train",
                   "date", "from_domain")
EXCLUSION_FIELDS = ("source", "source_file", "source_member", "label", "reason", "duplicate_of", "id")
BEGIN, END = "<!-- BEGIN GENERATED COUNTS -->", "<!-- END GENERATED COUNTS -->"


def prepare(raw_messages: Iterable[RawMessage]) -> tuple[list[dict], list[dict]]:
    """Pure pipeline over in-memory raw messages. Deterministic for a given input set."""
    records, excluded, seen_raw = [], [], {}
    ordered = sorted(raw_messages, key=lambda m: (SOURCE_ORDER.index(m.source), m.source_file,
                                                  m.source_member))
    for rm in ordered:
        label = map_label(rm.source, rm.original_label)
        ref = {"source": rm.source, "source_file": rm.source_file,
               "source_member": rm.source_member, "label": label}
        try:
            rec = normalize(rm)
        except Excluded as exc:
            excluded.append({**ref, "reason": exc.reason})
            continue
        rec["id"] = f"{rm.source}-{rec['raw_sha256'][:16]}"
        if rec["id"] in seen_raw:
            excluded.append({**ref, "reason": "exact_duplicate_raw", "duplicate_of": rec["id"]})
            continue
        seen_raw[rec["id"]] = True
        rec["label"] = label
        records.append(rec)

    records, removed = exact_duplicates(records)
    excluded.extend(removed)
    for r in records:
        r["simhash"] = simhash(r["body"])  # body only: campaigns rotate subjects
        r["n_tokens"] = len(tokens(r["body"]))
    clusters = near_duplicate_clusters(records)
    for r in records:
        r["near_dup_cluster"] = clusters[r["id"]]
    groups = assign_groups(records)
    for r in records:
        r["group_id"] = groups[r["id"]]
    splits = assign_splits(records)
    for r in records:
        r["split"] = splits[r["id"]]
    flag_sender_seen(records)
    excluded.sort(key=lambda e: (SOURCE_ORDER.index(e["source"]), e["source_file"], e["source_member"]))
    return records, excluded


def _csv(rows: list[dict], fields: tuple[str, ...]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for row in rows:
        w.writerow({k: ("" if row.get(k) is None else
                        (f"{row[k]:016x}" if k == "simhash" else row[k])) for k in fields})
    return buf.getvalue()


def compute_stats(records: list[dict], excluded: list[dict], manifest_text: str) -> dict:
    by_src_lbl: dict[str, Counter] = defaultdict(Counter)
    by_orig: Counter = Counter()
    dates: dict[str, list[str]] = defaultdict(list)
    split_dates: dict[str, list[str]] = defaultdict(list)
    for r in records:
        by_src_lbl[r["source"]][r["label"]] += 1
        by_orig[f"{r['source']}/{r['original_label']}"] += 1
        if r["date"]:
            dates[r["source"]].append(r["date"])
            split_dates[r["split"]].append(r["date"])
    cluster_sizes = Counter(r["near_dup_cluster"] for r in records)
    group_sizes = Counter(r["group_id"] for r in records)
    largest = max(group_sizes.items(), key=lambda kv: (kv[1], kv[0])) if group_sizes else ("", 0)
    largest_mix = Counter(r["label"] for r in records if r["group_id"] == largest[0])
    synth = sum(1 for r in records if r["is_synthetic"])
    label_totals = Counter(r["label"] for r in records)
    return {
        "labels": list(LABELS),
        "total": len(records),
        "real": len(records) - synth,
        "synthetic": synth,
        "synthetic_fraction": round(synth / len(records), 4) if records else 0.0,
        "by_label": {lbl: label_totals.get(lbl, 0) for lbl in LABELS},
        "by_source_label": {s: {lbl: by_src_lbl[s].get(lbl, 0) for lbl in LABELS}
                            for s in SOURCE_ORDER if s in by_src_lbl},
        "by_original_label": dict(sorted(by_orig.items())),
        "date_range_by_source": {s: [min(v)[:10], max(v)[:10]] for s, v in sorted(dates.items())},
        "missing_date_by_source": {s: sum(1 for r in records if r["source"] == s and not r["date"])
                                   for s in SOURCE_ORDER if s in by_src_lbl},
        "date_range_by_split": {s: [min(v)[:10], max(v)[:10]] for s, v in sorted(split_dates.items())},
        "split_fractions_target": SPLIT_FRACTIONS,
        "split_counts": split_counts(records),
        "split_totals": {s: sum(1 for r in records if r["split"] == s) for s in SPLITS},
        "split_counts_sender_disjoint": split_counts(records, "sender_disjoint"),
        "sender_overlap": sender_overlap_report(records),
        "exclusions_by_reason": dict(sorted(Counter(e["reason"] for e in excluded).items())),
        "exclusions_by_source_reason": {
            s: dict(sorted(Counter(e["reason"] for e in excluded if e["source"] == s).items()))
            for s in SOURCE_ORDER if any(e["source"] == s for e in excluded)},
        "near_duplicate": {
            "clusters_with_2plus": sum(1 for n in cluster_sizes.values() if n > 1),
            "messages_in_2plus_clusters": sum(n for n in cluster_sizes.values() if n > 1),
            "largest_cluster": max(cluster_sizes.values()) if cluster_sizes else 0,
        },
        "groups": {
            "count": len(group_sizes),
            "largest_size": largest[1],
            "largest_label_mix": dict(sorted(largest_mix.items())),
        },
        "leakage": leakage_report(records),
        "manifest_sha256": hashlib.sha256(manifest_text.encode()).hexdigest(),
    }


def render_counts(stats: dict) -> str:
    L = stats["labels"]
    lines = [BEGIN, "", f"Total messages: **{stats['total']}** "
             f"(real {stats['real']}, synthetic {stats['synthetic']} = "
             f"{stats['synthetic_fraction'] * 100:.1f}%).", "",
             "| Source | " + " | ".join(L) + " | total |", "|---" * (len(L) + 2) + "|"]
    for s in (x for x in SOURCE_ORDER if x in stats["by_source_label"]):
        row = stats["by_source_label"][s]
        lines.append(f"| {s} | " + " | ".join(str(row[x]) for x in L) + f" | {sum(row.values())} |")
    lines.append("| **all** | " + " | ".join(str(stats["by_label"][x]) for x in L)
                 + f" | {stats['total']} |")
    lines += ["", "| Original label | count |", "|---|---|"]
    lines += [f"| {k} | {stats['by_original_label'][k]} |" for k in sorted(stats["by_original_label"])]
    lines += ["", "| Split | " + " | ".join(L) + " | total | date range |", "|---" * (len(L) + 3) + "|"]
    for s in SPLITS:
        row = stats["split_counts"][s]
        dr = stats["date_range_by_split"].get(s, ["", ""])
        lines.append(f"| {s} | " + " | ".join(str(row[x]) for x in L)
                     + f" | {stats['split_totals'][s]} | {dr[0]} – {dr[1]} |")
    lines += ["", "| Source | date range | missing/invalid date |", "|---|---|---|"]
    for s in (x for x in SOURCE_ORDER if x in stats["date_range_by_source"]):
        a, b = stats["date_range_by_source"][s]
        lines.append(f"| {s} | {a} – {b} | {stats['missing_date_by_source'].get(s, 0)} |")
    lines += ["", "| Exclusion reason | count |", "|---|---|"]
    lines += [f"| {k} | {stats['exclusions_by_reason'][k]} |" for k in sorted(stats["exclusions_by_reason"])]
    nd, g = stats["near_duplicate"], stats["groups"]
    lines += ["", f"Near-duplicate clusters (≥2 members): {nd['clusters_with_2plus']} covering "
              f"{nd['messages_in_2plus_clusters']} messages; largest {nd['largest_cluster']}.",
              f"Leakage groups: {g['count']}; largest group {g['largest_size']} messages "
              f"{dict(sorted(g['largest_label_mix'].items()))}.",
              "Cross-split hard-key collisions (must all be 0): "
              + ", ".join(f"{k}={stats['leakage'][k]}" for k in sorted(stats["leakage"])) + "."]
    so = stats["sender_overlap"]
    lines += [f"Sender keys: {so['sender_keys']}; in more than one split: "
              f"{so['sender_keys_in_multiple_splits']} (soft constraint, see Splits).",
              "", "Sender-disjoint evaluation subset (validation/test messages whose sender "
              "never occurs in train):", "",
              "| Split | " + " | ".join(L) + " | total | sender seen in train |",
              "|---" * (len(L) + 3) + "|"]
    for s in ("validation", "test"):
        row = stats["split_counts_sender_disjoint"][s]
        lines.append(f"| {s} | " + " | ".join(str(row[x]) for x in L)
                     + f" | {so[s]['sender_disjoint']} | {so[s]['sender_seen_in_train']} |")
    lines += ["",
              f"manifest.csv sha256: `{stats['manifest_sha256']}`", "", END]
    return "\n".join(lines)


def update_data_card(card: Path, stats: dict) -> None:
    text = card.read_text()
    start, end = text.index(BEGIN), text.index(END) + len(END)
    card.write_text(text[:start] + render_counts(stats) + text[end:])


def collect(raw_dir: Path, include_real: bool) -> list[RawMessage]:
    from app.ml.dataset.readers import READERS
    msgs: list[RawMessage] = []
    if include_real:
        for sid in ("nazario", "spamassassin", "enron"):
            msgs.extend(READERS[sid](raw_dir))
    msgs.extend(synthetic.generate())
    return msgs


def write_outputs(records: list[dict], excluded: list[dict], data_dir: Path) -> dict:
    (data_dir / "processed").mkdir(parents=True, exist_ok=True)
    (data_dir / "manifest").mkdir(parents=True, exist_ok=True)
    with (data_dir / "processed" / "emails.jsonl").open("w") as f:
        for r in records:
            f.write(json.dumps({**r, "simhash": f"{r['simhash']:016x}"}, sort_keys=True,
                               ensure_ascii=False) + "\n")
    manifest = _csv(records, MANIFEST_FIELDS)
    (data_dir / "manifest" / "manifest.csv").write_text(manifest)
    (data_dir / "manifest" / "exclusions.csv").write_text(_csv(excluded, EXCLUSION_FIELDS))
    stats = compute_stats(records, excluded, manifest)
    (data_dir / "manifest" / "stats.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    if (data_dir / "DATA_CARD.md").exists():
        update_data_card(data_dir / "DATA_CARD.md", stats)
    return stats


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ap.add_argument("--no-real", action="store_true", help="synthetic only (smoke test)")
    args = ap.parse_args(argv)
    assert all(lbl in LABELS for lbl, _ in LABEL_MAP.values())
    records, excluded = prepare(collect(args.data_dir / "raw", not args.no_real))
    stats = write_outputs(records, excluded, args.data_dir)
    print(json.dumps({k: stats[k] for k in ("total", "real", "synthetic", "by_label",
                                            "split_totals", "leakage")}, indent=1))


if __name__ == "__main__":
    main()
