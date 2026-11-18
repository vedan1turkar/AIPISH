"""Download approved corpus files into data/raw/<source>/ and record provenance.

Usage: python -m app.ml.dataset.acquire [--data-dir DIR] [source ...]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

import httpx

from app.ml.dataset.sources import SOURCES, Source, SourceFile

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[4] / "data"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(sf: SourceFile, dest: Path) -> None:
    tmp = dest.with_suffix(dest.suffix + ".part")
    with httpx.stream("GET", sf.url, follow_redirects=True, timeout=60.0) as r:
        r.raise_for_status()
        with tmp.open("wb") as f:
            for chunk in r.iter_bytes(1 << 20):
                f.write(chunk)
    tmp.replace(dest)


def acquire_source(src: Source, data_dir: Path) -> list[dict]:
    out_dir = data_dir / "raw" / src.id
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "acquisition.json"
    previous = {e["name"]: e for e in json.loads(log_path.read_text())} if log_path.exists() else {}
    entries = []
    for sf in src.files:
        dest = out_dir / sf.name
        if not dest.exists():
            _download(sf, dest)
            acquired = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        else:
            acquired = previous.get(sf.name, {}).get("acquired_utc", "unknown")
        digest = sha256_file(dest)
        size = dest.stat().st_size
        if sf.sha256 and digest != sf.sha256:
            raise RuntimeError(f"{src.id}/{sf.name}: sha256 {digest} != pinned {sf.sha256}")
        if sf.size and size != sf.size:
            raise RuntimeError(f"{src.id}/{sf.name}: size {size} != expected {sf.size}")
        entries.append({"name": sf.name, "url": sf.url, "size": size, "sha256": digest,
                        "acquired_utc": acquired, "licence": src.licence})
    log_path.write_text(json.dumps(entries, indent=2) + "\n")
    return entries


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ap.add_argument("sources", nargs="*", default=list(SOURCES))
    args = ap.parse_args(argv)
    for sid in args.sources:
        for e in acquire_source(SOURCES[sid], args.data_dir):
            print(f"{sid}/{e['name']}: {e['size']} bytes sha256={e['sha256']}")


if __name__ == "__main__":
    main()
