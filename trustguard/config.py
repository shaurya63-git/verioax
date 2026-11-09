"""Configuration.

Two layers, deliberately separate:

* ``Settings`` - deployment settings from environment variables / ``.env`` (API keys, data directory, network limits).
  API keys are ``SecretStr``: they are never printed, logged, returned by the API or shown in the UI.
* ``Preferences`` - user-tunable analysis settings (thresholds, privacy switches) that the Settings page edits. They are
  stored as JSON in the data directory and contain no secrets.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _key(*names: str):
    return Field(default=None, validation_alias=AliasChoices(*names))


class Settings(BaseSettings):
    # env_ignore_empty: a blank line such as "VIRUSTOTAL_API_KEY=" copied from .env.example means "not set", not an empty key
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore", populate_by_name=True,
                                      env_ignore_empty=True)

    data_dir: Path = Field(default=Path("data/runtime"), validation_alias=AliasChoices("TRUSTGUARD_DATA_DIR", "data_dir"))
    api_url: str | None = Field(default=None, validation_alias=AliasChoices("TRUSTGUARD_API_URL", "api_url"))
    api_token: SecretStr | None = _key("TRUSTGUARD_API_TOKEN", "api_token")

    # live URL inspection limits (SSRF-guarded fetcher)
    fetch_timeout_s: float = Field(default=8.0, validation_alias=AliasChoices("TRUSTGUARD_FETCH_TIMEOUT_S", "fetch_timeout_s"))
    max_redirects: int = Field(default=5, validation_alias=AliasChoices("TRUSTGUARD_MAX_REDIRECTS", "max_redirects"))
    max_page_bytes: int = Field(default=1_500_000, validation_alias=AliasChoices("TRUSTGUARD_MAX_PAGE_BYTES", "max_page_bytes"))
    allowed_ports: tuple[int, ...] = (80, 443)
    user_agent: str = ("Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/124.0 Mobile Safari/537.36")

    # threat-intelligence and verification services (all optional)
    google_safe_browsing_key: SecretStr | None = _key("GOOGLE_SAFE_BROWSING_API_KEY", "google_safe_browsing_key")
    virustotal_key: SecretStr | None = _key("VIRUSTOTAL_API_KEY", "virustotal_key")
    urlhaus_key: SecretStr | None = _key("URLHAUS_AUTH_KEY", "urlhaus_key")
    phishtank_app_key: SecretStr | None = _key("PHISHTANK_APP_KEY", "phishtank_app_key")
    phishtank_username: str | None = Field(default=None, validation_alias=AliasChoices("PHISHTANK_USERNAME", "phishtank_username"))
    factcheck_key: SecretStr | None = _key("GOOGLE_FACTCHECK_API_KEY", "factcheck_key")
    openphish_feed_url: str = Field(default="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
                                    validation_alias=AliasChoices("OPENPHISH_FEED_URL", "openphish_feed_url"))

    # optional local LLM (explanations only; it never sees raw PII or page content)
    ollama_url: str = Field(default="http://localhost:11434", validation_alias=AliasChoices("OLLAMA_URL", "ollama_url"))
    ollama_model: str = Field(default="llama3.1:8b", validation_alias=AliasChoices("OLLAMA_MODEL", "ollama_model"))

    def configured_services(self) -> dict[str, bool]:
        return {
            "google_safe_browsing": self.google_safe_browsing_key is not None,
            "virustotal": self.virustotal_key is not None,
            "urlhaus": self.urlhaus_key is not None,
            "phishtank": self.phishtank_app_key is not None,
            "google_factcheck": self.factcheck_key is not None,
        }


class Preferences(BaseModel):
    """Analysis and privacy preferences (editable in the UI, persisted as JSON, no secrets)."""

    # detection
    pii_min_confidence: float = Field(0.50, ge=0.3, le=0.95)
    pii_review_threshold: float = Field(0.65, ge=0.3, le=0.95)
    leak_sweep_rounds: int = Field(2, ge=0, le=3)
    use_ner: bool = True                       # spaCy NER for names, when installed
    scam_sensitivity: Literal["conservative", "balanced", "aggressive"] = "balanced"
    language: Literal["auto", "en", "hi", "hinglish"] = "auto"

    # network behaviour ("local processing mode" = both off)
    network_checks: bool = True                # visit links in the guarded backend fetcher, TLS + RDAP lookups
    intel_lookups: bool = True                 # query configured threat-intelligence services
    openphish_feed: bool = False               # download the OpenPhish community feed (cached 12 h)
    factcheck_lookups: bool = True             # query Google Fact Check Tools for extracted claims (if a key is set)
    llm_explanations: bool = False             # local Ollama explanations (redacted text only)

    # privacy
    auto_redact: bool = True                   # redact PII in every scan (the redacted text is what gets stored)
    store_history: bool = True
    retention_days: int = Field(30, ge=1, le=365)
    max_urls_per_scan: int = Field(5, ge=1, le=10)

    @property
    def local_mode(self) -> bool:
        return not (self.network_checks or self.intel_lookups or self.openphish_feed or self.factcheck_lookups)

    def fingerprint(self) -> str:
        """Stable hash of the analysis-relevant settings: identical input + identical fingerprint = identical score."""
        blob = json.dumps(self.model_dump(), sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()[:12]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def preferences_path(settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    return Path(s.data_dir) / "preferences.json"


def load_preferences(settings: Settings | None = None) -> Preferences:
    p = preferences_path(settings)
    if p.exists():
        try:
            return Preferences.model_validate_json(p.read_text(encoding="utf-8"))
        except ValueError:
            pass                                 # corrupt or outdated file: fall back to defaults
    return Preferences()


def save_preferences(prefs: Preferences, settings: Settings | None = None) -> Path:
    p = preferences_path(settings)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(prefs.model_dump_json(indent=2), encoding="utf-8")
    return p
