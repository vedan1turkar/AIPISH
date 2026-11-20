"""LLM-assisted forensic summary (P3): local Mistral via Ollama.

The summary is an AI-generated interpretation layered on top of the
deterministic pipeline. If the LLM fails for any reason the response still
carries the evidence pack, the unavailable checks and the system verdicts,
with status explaining why there is no narrative. Nothing else is affected.
"""
from __future__ import annotations

import logging
import time

from app.llm import client as C
from app.llm.evidence import build_pack
from app.llm.prompt import OUTPUT_SCHEMA, build_messages
from app.llm.validate import InvalidOutput, parse, validate

log = logging.getLogger("aipish.llm")

AI_LABEL = ("AI-generated interpretation (Mistral via local Ollama). It may be wrong; rely on the "
            "cited evidence items and the system verdicts, not on this text alone.")


def status() -> dict:
    cfg = C.LLMConfig.load()
    try:
        info = C.model_info(cfg)
    except C.LLMUnavailable as exc:
        return {"status": "unavailable", "reason": str(exc), "model": cfg.model, "local_only": True}
    return {"status": "ok", "model": info["name"], "digest": info["digest"],
            "details": info.get("details"), "local_only": True, "timeout_seconds": cfg.timeout}


def forensic_summary(analysis: dict, ml: dict | None, explanation: dict | None) -> dict:
    t0 = time.monotonic()
    pack = build_pack(analysis, ml, explanation)
    from app.llm.recommend import financial_context, general_recommendations
    fin = financial_context(pack)            # deterministic: shown even when the LLM fails
    cfg = C.LLMConfig.load()
    base = {
        "ai_generated": True, "label": AI_LABEL,
        "model": {"provider": "ollama", "name": cfg.model, "digest": None, "local": True},
        "summary": None, "assessment": None, "findings": [], "rejected_findings": [],
        "recommended_actions": [], "limitations": [], "validation": None,
        "recommendations": general_recommendations(fin), "rejected_recommendations": [],
        "financial_context": fin, "recommendation_policy": "p4.2-constrained",
        "evidence": pack.items, "unavailable_information": pack.unavailable,
        "system_verdicts": pack.system_verdicts,
        "security": {"injection_patterns_detected": pack.injection_patterns,
                     "redactions": dict(pack.redactions), "body_chars_sent": len(pack.body_excerpt),
                     "endpoint_local_only": True},
        "reason": None,
    }

    def done(status: str, **extra) -> dict:
        out = {**base, **extra, "status": status, "latency_ms": int((time.monotonic() - t0) * 1000)}
        log.info("llm summary status=%s latency_ms=%s evidence=%d injection=%s", status, out["latency_ms"],
                 len(pack.items), ",".join(pack.injection_patterns) or "-")
        return out

    try:
        info = C.model_info(cfg)
        base["model"].update(name=info["name"], digest=info["digest"])
    except C.LLMUnavailable as exc:
        return done("unavailable", reason=str(exc))

    system, user, _ = build_messages(pack)
    last_error = None
    for attempt in range(2):
        prompt = user if attempt == 0 else (user + f"\n\nYour previous reply was rejected ({last_error}). "
                                            "Reply again with complete, shorter JSON only.")
        try:
            content, _secs = C.chat_json(cfg, system, prompt, OUTPUT_SCHEMA)
            data = parse(content)
        except C.LLMTimeout as exc:
            return done("timeout", reason=str(exc))
        except C.LLMUnavailable as exc:
            return done("unavailable", reason=str(exc))
        except (InvalidOutput, ValueError) as exc:
            last_error = str(exc)
            continue
        return done("ok", attempts=attempt + 1, **validate(data, pack))
    return done("invalid_output", reason=f"model output rejected after 2 attempts: {last_error}")
