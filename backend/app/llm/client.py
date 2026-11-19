"""Minimal Ollama client restricted to local endpoints (email data never leaves the host)."""
from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.core.config import env

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class LLMUnavailable(Exception):
    pass


class LLMTimeout(Exception):
    pass


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    model: str
    timeout: float
    num_ctx: int
    seed: int

    @staticmethod
    def load() -> "LLMConfig":
        return LLMConfig(base_url=(env("OLLAMA_BASE_URL") or "http://127.0.0.1:11434").rstrip("/"),
                         model=env("OLLAMA_MODEL") or "mistral",
                         timeout=float(env("LLM_TIMEOUT_SECONDS") or 120),
                         num_ctx=int(env("LLM_NUM_CTX") or 8192),
                         seed=int(env("LLM_SEED") or 7))


def assert_local(base_url: str) -> None:
    """Only loopback, or hosts explicitly listed in OLLAMA_ALLOWED_HOSTS (e.g. a
    Docker-network service name). Never a public/cloud endpoint by default."""
    host = (urlsplit(base_url).hostname or "").lower()
    extra = {h.strip().lower() for h in (env("OLLAMA_ALLOWED_HOSTS") or "").split(",") if h.strip()}
    if host not in LOCAL_HOSTS | extra:
        raise LLMUnavailable(f"refusing non-local LLM endpoint host '{host}'")


def _model_matches(name: str, wanted: str) -> bool:
    """'mistral' matches any tag of mistral; 'mistral:7b' must match exactly."""
    return name == wanted if ":" in wanted else name.split(":")[0] == wanted


def model_info(cfg: LLMConfig) -> dict:
    """Return {'name', 'digest'} of the configured model or raise LLMUnavailable."""
    assert_local(cfg.base_url)
    try:
        r = httpx.get(f"{cfg.base_url}/api/tags", timeout=5.0)
        r.raise_for_status()
        models = r.json().get("models") or []
    except (httpx.HTTPError, ValueError) as exc:
        raise LLMUnavailable(f"Ollama not reachable at {cfg.base_url} ({type(exc).__name__})") from exc
    for m in models:
        if _model_matches(m.get("name", ""), cfg.model):
            return {"name": m["name"], "digest": m.get("digest"), "details": m.get("details", {})}
    raise LLMUnavailable(f"model '{cfg.model}' is not pulled in Ollama (run: ollama pull {cfg.model})")


def chat_json(cfg: LLMConfig, system: str, user: str, schema: dict) -> tuple[str, float]:
    """One deterministic chat call with JSON-schema constrained output. Returns (content, seconds)."""
    assert_local(cfg.base_url)
    body = {"model": cfg.model, "stream": False, "format": schema,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": 0, "seed": cfg.seed, "num_ctx": cfg.num_ctx, "num_predict": 1600}}
    t0 = time.monotonic()
    try:
        r = httpx.post(f"{cfg.base_url}/api/chat", json=body, timeout=cfg.timeout)
    except httpx.TimeoutException as exc:
        raise LLMTimeout(f"no response within {cfg.timeout:.0f}s") from exc
    except httpx.HTTPError as exc:
        raise LLMUnavailable(f"Ollama request failed ({type(exc).__name__})") from exc
    if r.status_code == 404:
        raise LLMUnavailable(f"model '{cfg.model}' not found by Ollama")
    if r.status_code >= 400:
        raise LLMUnavailable(f"Ollama returned HTTP {r.status_code}")
    try:
        payload = r.json()
        content = payload["message"]["content"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("Ollama response missing message content") from exc
    if payload.get("done_reason") == "length":
        raise ValueError("model output truncated at the token limit")
    return content, time.monotonic() - t0
