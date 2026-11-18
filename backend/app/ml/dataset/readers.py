"""Read raw messages from the locally acquired archives (never from the network)."""
from __future__ import annotations

import hashlib
import heapq
import json
import mailbox
import tarfile
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from app.ml.dataset.normalize import RawMessage
from app.ml.dataset.sources import ENRON, NAZARIO, SPAMASSASSIN

ENRON_SENT_FOLDERS = frozenset({"sent", "sent_items", "_sent_mail"})
ENRON_PER_CUSTODIAN = 25
ENRON_SUBSET_DIR = "sent_subset"


def read_nazario(raw_dir: Path) -> Iterator[RawMessage]:
    for sf in NAZARIO.files:
        box = mailbox.mbox(raw_dir / "nazario" / sf.name, create=False)
        try:
            for i, key in enumerate(box.keys()):
                yield RawMessage("nazario", sf.name, f"{sf.name}#{i}", "phishing", box.get_bytes(key))
        finally:
            box.close()


def read_spamassassin(raw_dir: Path) -> Iterator[RawMessage]:
    for sf in SPAMASSASSIN.files:
        with tarfile.open(raw_dir / "spamassassin" / sf.name, "r:bz2") as tar:
            members = sorted((m for m in tar.getmembers() if m.isfile()), key=lambda m: m.name)
            for m in members:
                top, _, base = m.name.partition("/")
                if base == "cmds" or not base:
                    continue
                data = tar.extractfile(m).read()  # type: ignore[union-attr]
                yield RawMessage("spamassassin", sf.name, m.name, top, data)


def _enron_rank(path: str) -> int:
    return int(hashlib.sha256(path.encode()).hexdigest()[:16], 16)


def build_enron_subset(raw_dir: Path, per_custodian: int = ENRON_PER_CUSTODIAN) -> Path:
    """One streaming pass over the tarball: per custodian keep the
    `per_custodian` sent-folder messages with the smallest sha256(path), a
    deterministic sample. The subset is written to disk with an index."""
    src = raw_dir / "enron"
    out = src / ENRON_SUBSET_DIR
    index_path = out / "index.json"
    if index_path.exists():
        return out
    heaps: dict[str, list[tuple[int, str, bytes]]] = defaultdict(list)
    with tarfile.open(src / ENRON.files[0].name, "r|gz") as tar:
        for m in tar:
            if not m.isfile():
                continue
            parts = m.name.split("/")  # maildir/<custodian>/<folder>/...
            if len(parts) < 4 or parts[0] != "maildir" or parts[2].lower() not in ENRON_SENT_FOLDERS:
                continue
            rank = -_enron_rank(m.name)  # max-heap of the smallest ranks
            heap = heaps[parts[1]]
            if len(heap) < per_custodian:
                heapq.heappush(heap, (rank, m.name, tar.extractfile(m).read()))  # type: ignore[union-attr]
            elif rank > heap[0][0]:
                heapq.heapreplace(heap, (rank, m.name, tar.extractfile(m).read()))  # type: ignore[union-attr]
    index = []
    for custodian in sorted(heaps):
        for _, name, data in sorted(heaps[custodian], key=lambda t: t[1]):
            dest = out / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            index.append(name)
    index_path.write_text(json.dumps({"per_custodian": per_custodian, "members": index}, indent=1))
    return out


def read_enron(raw_dir: Path) -> Iterator[RawMessage]:
    subset = build_enron_subset(raw_dir)
    index = json.loads((subset / "index.json").read_text())
    for name in index["members"]:
        yield RawMessage("enron", ENRON.files[0].name, name, "sent_mail", (subset / name).read_bytes())


READERS = {"nazario": read_nazario, "spamassassin": read_spamassassin, "enron": read_enron}
