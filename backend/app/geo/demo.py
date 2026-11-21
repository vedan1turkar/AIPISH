"""SIMULATED geolocation for the synthetic demo emails (P5g). Offline, opt-in, never in production.

Only analyses whose raw bytes match a committed synthetic demo fixture are touched. Every row is stored
with ``source="simulated-demo"`` and ``simulated=True`` and shown with a "SIMULATED demo data" tag.
Locations are generic city centroids and ASNs come from the RFC 5398 documentation range
(AS64496-AS64511): they describe no real network, victim or sender.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.models import Analysis, GeoObservation, utcnow
from app.geo.service import ip_roles

SOURCE = "simulated-demo"
FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "demo"

# fixed demo assignments for the IPs used by the synthetic fixtures; anything else gets a stable pick below
_KNOWN: dict[str, dict] = {
    "96.7.128.175": {"city": "Frankfurt am Main", "region": "Hesse", "country": "DE", "lat": 50.11, "lon": 8.68,
                     "asn": "AS64500", "org": "SIMULATED Hosting Provider A", "anonymity": {"hosting": True}},
    "185.220.101.1": {"city": "Amsterdam", "region": "North Holland", "country": "NL", "lat": 52.37, "lon": 4.90,
                      "asn": "AS64501", "org": "SIMULATED Anonymity Network", "anonymity": {"tor": True, "hosting": True}},
    "172.217.14.99": {"city": "Ashburn", "region": "Virginia", "country": "US", "lat": 39.04, "lon": -77.49,
                      "asn": "AS64502", "org": "SIMULATED Mail Provider", "anonymity": {"hosting": True}},
    "2001:4860:4860::8888": {"city": "Singapore", "region": None, "country": "SG", "lat": 1.29, "lon": 103.85,
                             "asn": "AS64503", "org": "SIMULATED Transit Network", "anonymity": {}},
}
_POOL = [
    {"city": "Warsaw", "region": "Masovia", "country": "PL", "lat": 52.23, "lon": 21.01},
    {"city": "São Paulo", "region": "São Paulo", "country": "BR", "lat": -23.55, "lon": -46.63},
    {"city": "Lagos", "region": "Lagos", "country": "NG", "lat": 6.52, "lon": 3.38},
    {"city": "Mumbai", "region": "Maharashtra", "country": "IN", "lat": 19.08, "lon": 72.88},
    {"city": "Toronto", "region": "Ontario", "country": "CA", "lat": 43.65, "lon": -79.38},
    {"city": "Sydney", "region": "New South Wales", "country": "AU", "lat": -33.87, "lon": 151.21},
]


def _location(ip: str) -> dict:
    if ip in _KNOWN:
        return _KNOWN[ip]
    h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
    base = _POOL[h % len(_POOL)]
    return {**base, "asn": f"AS{64504 + h % 8}", "org": "SIMULATED Network", "anonymity": {}}


def fixture_hashes() -> set[str]:
    return {hashlib.sha256(p.read_bytes()).hexdigest() for p in FIXTURES.rglob("*.eml")}


def seed_simulated_geo(db: Session) -> int:
    """Insert SIMULATED observations for public IPs of synthetic demo analyses. Idempotent; returns rows added."""
    hashes = fixture_hashes()
    added = 0
    for rec in db.query(Analysis).filter(Analysis.raw_sha256.in_(hashes)).all():
        existing = {o.ip for o in db.query(GeoObservation).filter_by(analysis_id=rec.id, source=SOURCE).all()}
        for ip in ip_roles(rec):
            if ip in existing:
                continue
            loc = _location(ip)
            db.add(GeoObservation(analysis_id=rec.id, ip=ip, latitude=loc["lat"], longitude=loc["lon"],
                                  country=loc["country"], region=loc.get("region"), city=loc.get("city"),
                                  asn=loc["asn"], org=loc["org"], anonymity_json=loc.get("anonymity") or {},
                                  source=SOURCE, simulated=True, fetched_at=utcnow()))
            added += 1
    db.commit()
    return added
