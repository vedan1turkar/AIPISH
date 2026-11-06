"""Environment strategy: process env > env file > defaults; no real credentials used."""
from __future__ import annotations

from pathlib import Path

import pytest

import app.core.config as core_config
from app.core.config import Settings, env
from app.enrichment.config import EnrichmentConfig

REPO_ROOT = Path(core_config.__file__).resolve().parents[3]
PROVIDER_VARS = ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "IPINFO_TOKEN",
                 "MAXMIND_GEOIP2_DB", "ENRICH_ENABLE_DNS", "ENRICH_HTTP_TIMEOUT")
DUMMY = "dummy-not-a-real-key"


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """Point the loader at a temp env file; clear any real provider vars."""
    for name in PROVIDER_VARS:
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / ".env"
    monkeypatch.setattr(core_config, "ENV_FILE", path)
    core_config.reload_env_file()
    yield path
    core_config.reload_env_file()


def test_default_env_file_is_repo_root(monkeypatch):
    monkeypatch.delenv("APP_ENV_FILE", raising=False)
    assert (REPO_ROOT / "backend" / "app").is_dir()
    assert core_config._resolve_env_file() == REPO_ROOT / ".env"


def test_app_env_file_override(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV_FILE", str(tmp_path / "custom.env"))
    assert core_config._resolve_env_file() == tmp_path / "custom.env"


def test_provider_settings_load_from_env_file(env_file):
    env_file.write_text(
        f"VIRUSTOTAL_API_KEY={DUMMY}\nABUSEIPDB_API_KEY={DUMMY}\n"
        f"SHODAN_API_KEY={DUMMY}\nIPINFO_TOKEN={DUMMY}\n"
        "ENRICH_ENABLE_DNS=0\nENRICH_HTTP_TIMEOUT=7\n"
    )
    cfg = EnrichmentConfig()
    assert cfg.credential_status() == {
        "virustotal": True, "abuseipdb": True, "shodan": True, "ipinfo": True,
        "maxmind_geoip2_db": False,
    }
    assert cfg.enable_dns is False
    assert cfg.http_timeout_seconds == 7.0


def test_process_env_overrides_env_file(env_file, monkeypatch):
    env_file.write_text("ENRICH_HTTP_TIMEOUT=7\n")
    monkeypatch.setenv("ENRICH_HTTP_TIMEOUT", "3")
    assert EnrichmentConfig().http_timeout_seconds == 3.0


def test_missing_env_file_uses_defaults_and_skips_credentials(env_file):
    assert not env_file.exists()            # Docker case: no file on disk
    cfg = EnrichmentConfig()
    assert not any(cfg.credential_status().values())
    assert cfg.enable_dns is True
    assert cfg.http_timeout_seconds == 15.0


def test_empty_values_fall_back_to_defaults(env_file):
    env_file.write_text("VIRUSTOTAL_API_KEY=\nENRICH_HTTP_TIMEOUT=\nAPP_PORT=\n")
    cfg = EnrichmentConfig()
    assert cfg.virustotal_api_key is None
    assert cfg.http_timeout_seconds == 15.0
    assert Settings(_env_file=env_file).port == 8000


def test_settings_reads_app_vars_from_env_file(env_file, monkeypatch):
    monkeypatch.delenv("APP_PORT", raising=False)
    env_file.write_text("APP_PORT=9123\n")
    assert Settings(_env_file=env_file).port == 9123


def test_credentials_never_in_repr(env_file):
    env_file.write_text(f"VIRUSTOTAL_API_KEY={DUMMY}\nSHODAN_API_KEY={DUMMY}\n"
                        f"ABUSEIPDB_API_KEY={DUMMY}\nIPINFO_TOKEN={DUMMY}\n")
    cfg = EnrichmentConfig()
    assert DUMMY not in repr(cfg)
    assert DUMMY not in str(cfg.credential_status())


def test_env_helper_precedence(env_file, monkeypatch):
    env_file.write_text("AIPISH_TEST_VAR=from-file\n")
    assert env("AIPISH_TEST_VAR") == "from-file"
    monkeypatch.setenv("AIPISH_TEST_VAR", "from-process")
    assert env("AIPISH_TEST_VAR") == "from-process"
    assert env("AIPISH_UNSET_VAR", "fallback") == "fallback"
