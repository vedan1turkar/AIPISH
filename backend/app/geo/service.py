"""Infrastructure geolocation for an analysis or a campaign (P5g).

Data rules (see docs/geo/README.md):
- NO lookups here. Only data already stored is used, in this order of preference per IP:
  1. the latest consented threat-intel run (IPinfo ``approx_coordinates``; Tor list; AbuseIPDB);
  2. the upload-time IP-geolocation enrichment (``ipgeo_http``, ip-api.com);
  3. stored ``geo_observation`` rows (today only SIMULATED demo data, source ``simulated-demo``).
- Only public IPs from the relay chain, the origin candidate, IP-literal URL hosts and recorded DNS
  resolutions of URL hosts. Private/reserved addresses are never returned; nor is any recipient data.
- Anonymity signals (Tor/VPN/proxy/relay/hosting) are reported only when a stored provider result backs
  them; otherwise ``None`` ("not available"), never ``False``.
- Stale and SIMULATED results are flagged on every point.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.core.models import Analysis, Campaign, CampaignMember, GeoObservation, ThreatIntelRun
from app.enrichment.iocs import is_global_ip

DISCLAIMER = ("Approximate infrastructure location from IP data. It is not the sender's physical location "
              "and does not identify a person. VPN, proxy, hosting and Tor distort results.")
ACCURACY_NOTE = ("Approximate: IP geolocation is typically country- or city-level and can be wrong by hundreds "
                 "of kilometres; hosting, anycast, VPN and proxy addresses show the provider's network, not a person.")
RELAY_ORDER_LABEL = "relay order, not a physical route"

ROLE_ORDER = ("origin_candidate", "untrusted_relay", "trusted_relay", "url_host_ip")
SIGNALS = ("tor", "vpn", "proxy", "relay", "hosting")
MAX_IPS_PER_ANALYSIS = 50
MAX_CAMPAIGN_POINTS = 200


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _iso(dt: datetime | None) -> str | None:
    dt = _aware(dt)
    return dt.isoformat() if dt else None


def _float(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f else None          # NaN guard


def _valid_coords(lat: float | None, lon: float | None) -> bool:
    return lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180


# ── which IPs, in which roles ───────────────────────────────────────────────
def ip_roles(rec: Analysis) -> dict[str, dict]:
    """Public IPs of interest → {"roles": [...], "hops": [...], "via_host": str|None}. Order-stable."""
    fx = rec.forensics_json or {}
    out: dict[str, dict] = {}

    def add(ip: str | None, role: str, hop: int | None = None, via: str | None = None) -> None:
        if not ip:
            return
        ip = str(ip).strip().strip("[]")
        if not is_global_ip(ip):
            return                      # private / reserved / malformed: never shown
        e = out.setdefault(ip, {"roles": [], "hops": [], "via_host": None})
        if role not in e["roles"]:
            e["roles"].append(role)
        if hop is not None and hop not in e["hops"]:
            e["hops"].append(hop)
        if via and not e["via_host"]:
            e["via_host"] = via

    add(fx.get("verified_originating_ip") or fx.get("earliest_candidate_ip"), "origin_candidate")
    for hop in fx.get("relay_chain") or []:
        hop = hop or {}
        add(hop.get("from_ip"), "trusted_relay" if hop.get("trusted") else "untrusted_relay", hop.get("index"))
    for ip in fx.get("candidate_ips") or []:
        if str(ip).strip() not in out:            # already classified by its relay hop (trusted/untrusted)
            add(ip, "untrusted_relay")
    hosts: set[str] = set()
    for u in rec.urls or []:
        host = (u or {}).get("host") or urlsplit(str((u or {}).get("url") or "")).hostname
        if not host:
            continue
        host = str(host).strip("[]").lower()
        if is_global_ip(host):
            add(host, "url_host_ip", via=host)
        else:
            hosts.add(host)
    # recorded DNS resolutions of URL hosts (upload-time enrichment): A records only
    for r in (rec.enrichment_json or {}).get("results") or []:
        if r.get("provider") != "dns" or r.get("status") != "ok":
            continue
        host = str((r.get("ioc") or {}).get("value") or "").lower()
        if host not in hosts:
            continue
        for a in ((r.get("evidence") or {}).get("records") or {}).get("A") or []:
            add(a, "url_host_ip", via=host)
    for e in out.values():
        e["roles"].sort(key=ROLE_ORDER.index)
        e["hops"].sort()
    return dict(list(out.items())[:MAX_IPS_PER_ANALYSIS])


# ── stored location sources ─────────────────────────────────────────────────
def latest_consented_run(db: Session, analysis_id: str) -> ThreatIntelRun | None:
    return (db.query(ThreatIntelRun)
            .filter(ThreatIntelRun.analysis_id == analysis_id, ThreatIntelRun.consent_granted.is_(True))
            .order_by(ThreatIntelRun.version.desc()).first())


def _intel_by_ip(run: ThreatIntelRun | None) -> dict[str, dict[str, dict]]:
    """ip → provider → stored result dict (only results that carry data)."""
    out: dict[str, dict[str, dict]] = {}
    if run is None:
        return out
    for entry in (run.result_json or {}).get("indicators") or []:
        if entry.get("indicator_type") != "ip":
            continue
        for r in entry.get("results") or []:
            out.setdefault(str(entry.get("indicator")), {})[r.get("provider")] = r
    return out


def _from_ipinfo(r: dict, simulated: bool) -> dict | None:
    if r.get("status") not in ("record_found", "reported_clean_no_flags", "malicious_or_flagged"):
        return None
    d = r.get("data") or {}
    lat = lon = None
    if isinstance(d.get("approx_coordinates"), str) and "," in d["approx_coordinates"]:
        a, b = d["approx_coordinates"].split(",", 1)
        lat, lon = _float(a), _float(b)
    return {"lat": lat, "lon": lon, "country": d.get("country"), "region": d.get("region"), "city": d.get("city"),
            "asn": d.get("asn"), "org": d.get("org"), "isp": None,
            "source": "IPinfo (consented threat-intel run)", "provider": "ipinfo",
            "fetched_at": r.get("fetched_at"), "stale": r.get("cache_state") == "stale", "simulated": simulated,
            # P5a-live: real IPinfo data marks anycast addresses (e.g. 8.8.8.8); their city is a representative point
            "anycast": d.get("anycast") is True}


def _enrichment_geo(rec: Analysis) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in (rec.enrichment_json or {}).get("results") or []:
        if r.get("provider") != "ipgeo_http" or r.get("status") != "ok":
            continue
        loc = (r.get("evidence") or {}).get("network_location") or {}
        ip = str((r.get("ioc") or {}).get("value") or "")
        asn = (loc.get("as") or "").split(" ", 1)[0] or None
        out[ip] = {"lat": _float(loc.get("latitude")), "lon": _float(loc.get("longitude")),
                   "country": loc.get("country"), "region": loc.get("region"), "city": loc.get("city"),
                   "asn": asn, "org": loc.get("org"), "isp": loc.get("isp"),
                   "source": "ip-api.com (enrichment at upload)", "provider": "ipgeo_http",
                   "fetched_at": _iso(rec.created_at), "stale": False, "simulated": False}
    return out


def _observations(db: Session, analysis_id: str) -> dict[str, GeoObservation]:
    rows = (db.query(GeoObservation).filter(GeoObservation.analysis_id == analysis_id)
            .order_by(GeoObservation.fetched_at.desc()).all())
    out: dict[str, GeoObservation] = {}
    for row in rows:
        out.setdefault(row.ip, row)
    return out


def _from_observation(o: GeoObservation) -> dict:
    return {"lat": o.latitude, "lon": o.longitude, "country": o.country, "region": o.region, "city": o.city,
            "asn": o.asn, "org": o.org, "isp": None,
            "source": ("SIMULATED demo data (synthetic)" if o.simulated else o.source), "provider": o.source,
            "fetched_at": _iso(o.fetched_at), "stale": False, "simulated": bool(o.simulated)}


# ── anonymity signals ───────────────────────────────────────────────────────
def _signals(ip: str, intel: dict[str, dict], obs: GeoObservation | None) -> dict:
    """Each signal: {"value": True|False|None, "source": str|None}. None = not available (never assumed)."""
    sig: dict[str, dict] = {s: {"value": None, "source": None} for s in SIGNALS}
    simulated = False

    def put(name: str, value: bool, source: str) -> None:
        cur = sig[name]
        if cur["value"] is True:
            return                         # any provider reporting True wins; keep its source
        if value is True or cur["value"] is None:
            sig[name] = {"value": value, "source": source}

    ipinfo = intel.get("ipinfo")
    if ipinfo and (ipinfo.get("data") or {}).get("privacy_flags_returned"):
        d = ipinfo["data"]
        for s in SIGNALS:
            v = d.get(f"is_{s}")
            if isinstance(v, bool):
                put(s, v, "IPinfo privacy flags")
    tor = intel.get("tor")
    if tor and tor.get("status") in ("malicious_or_flagged", "no_record"):
        put("tor", tor["status"] == "malicious_or_flagged", "Tor bulk exit list")
    abuse = intel.get("abuseipdb")
    if abuse and abuse.get("status") in ("malicious_or_flagged", "no_record", "record_found",
                                         "reported_clean_no_flags"):
        d = abuse.get("data") or {}
        if isinstance(d.get("is_tor_provider_reported"), bool):
            put("tor", d["is_tor_provider_reported"], "AbuseIPDB")
        usage = str(d.get("usage_type") or "").lower()
        if usage:
            put("hosting", "hosting" in usage or "data center" in usage, f"AbuseIPDB usage type: {d.get('usage_type')}")
    if obs is not None and isinstance(obs.anonymity_json, dict):
        for s in SIGNALS:
            v = obs.anonymity_json.get(s)
            if isinstance(v, bool) and sig[s]["value"] is None:
                sig[s] = {"value": v, "source": "SIMULATED demo data" if obs.simulated else obs.source}
                simulated = simulated or bool(obs.simulated)
    return {"signals": sig, "simulated": simulated,
            "any_data": any(v["value"] is not None for v in sig.values())}


# ── public builders ─────────────────────────────────────────────────────────
def analysis_geo(db: Session, rec: Analysis) -> dict:
    roles = ip_roles(rec)
    run = latest_consented_run(db, rec.id)
    run_sim = bool((run.result_json or {}).get("simulated")) if run else False
    intel = _intel_by_ip(run)
    enr = _enrichment_geo(rec)
    obs = _observations(db, rec.id)
    points, unlocated, anonymity = [], [], []
    for ip, info in roles.items():
        loc = None
        if "ipinfo" in intel.get(ip, {}):
            loc = _from_ipinfo(intel[ip]["ipinfo"], run_sim)
        if (loc is None or not _valid_coords(loc["lat"], loc["lon"])) and ip in enr:
            loc = enr[ip]
        if (loc is None or not _valid_coords(loc["lat"], loc["lon"])) and ip in obs:
            loc = _from_observation(obs[ip])
        base = {"ip": ip, "role": info["roles"][0], "roles": info["roles"], "hops": info["hops"],
                "hop": info["hops"][0] if info["hops"] else None, "via_host": info["via_host"]}
        if loc is not None and _valid_coords(loc["lat"], loc["lon"]):
            points.append({**base, **loc, "accuracy_note": ACCURACY_NOTE})
        else:
            partial = {k: loc.get(k) for k in ("country", "asn", "org", "source")} if loc else {}
            unlocated.append({**base, **partial, "reason": "no location data"})
        a = _signals(ip, intel.get(ip, {}), obs.get(ip))
        anonymity.append({"ip": ip, "role": base["role"], **a})
    relay_order = [p["ip"] for p in sorted((p for p in points if p["hop"] is not None), key=lambda p: p["hop"])]
    return {
        "analysis_id": rec.id,
        "disclaimer": DISCLAIMER,
        "accuracy_note": ACCURACY_NOTE,
        "relay_order_label": RELAY_ORDER_LABEL,
        "points": points,
        "unlocated": unlocated,
        "anonymity": anonymity,
        "relay_order": relay_order,
        "counts": {"ips": len(roles), "located": len(points), "unlocated": len(unlocated)},
        "provenance": {
            "lookups_performed": False,
            "intel_run": ({"version": run.version, "created_at": _iso(run.created_at), "simulated": run_sim,
                           "offline": bool(run.offline)} if run else None),
            "enrichment_geo": bool(enr),
            "simulated_present": any(p["simulated"] for p in points) or any(a["simulated"] for a in anonymity),
            "stale_present": any(p["stale"] for p in points),
            "sources": sorted({p["source"] for p in points}),
        },
    }


def campaign_geo(db: Session, camp: Campaign) -> dict:
    member_ids = [m.analysis_id for m in db.query(CampaignMember).filter_by(campaign_id=camp.id).all()]
    merged: dict[str, dict] = {}
    unlocated: dict[str, dict] = {}
    for aid in member_ids:
        rec = db.get(Analysis, aid)
        if rec is None:
            continue
        g = analysis_geo(db, rec)
        for p in g["points"]:
            m = merged.setdefault(p["ip"], {**p, "members": [], "roles": []})
            if aid not in m["members"]:
                m["members"].append(aid)
            for r in p["roles"]:
                if r not in m["roles"]:
                    m["roles"].append(r)
            m["simulated"] = m["simulated"] or p["simulated"]
            m["stale"] = m["stale"] or p["stale"]
        for u in g["unlocated"]:
            if u["ip"] in merged:
                continue
            e = unlocated.setdefault(u["ip"], {**u, "members": []})
            if aid not in e["members"]:
                e["members"].append(aid)
    for ip in list(unlocated):
        if ip in merged:
            unlocated.pop(ip)
    points = []
    for p in merged.values():
        p["roles"].sort(key=ROLE_ORDER.index)
        p["role"] = p["roles"][0]
        p["member_count"] = len(p["members"])
        p.pop("hops", None)
        p.pop("hop", None)
        points.append(p)
    points.sort(key=lambda p: (-p["member_count"], p["ip"]))
    un = sorted(unlocated.values(), key=lambda u: (-len(u["members"]), u["ip"]))
    for u in un:
        u["member_count"] = len(u["members"])
        u.pop("hops", None)
        u.pop("hop", None)
    return {
        "campaign_id": camp.id,
        "disclaimer": DISCLAIMER,
        "accuracy_note": ACCURACY_NOTE,
        "points": points[:MAX_CAMPAIGN_POINTS],
        "unlocated": un[:MAX_CAMPAIGN_POINTS],
        "counts": {"members": len(member_ids), "located": len(points), "unlocated": len(un),
                   "truncated": len(points) > MAX_CAMPAIGN_POINTS or len(un) > MAX_CAMPAIGN_POINTS},
        "provenance": {"lookups_performed": False,
                       "simulated_present": any(p["simulated"] for p in points),
                       "stale_present": any(p["stale"] for p in points),
                       "sources": sorted({p["source"] for p in points})},
    }
