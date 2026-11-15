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
    # 6-digit PIN that moderators enter at sign-up and sign-in. Kept out of the code on purpose: the repository is public.
    moderator_pin: SecretStr | None = _key("VERIOAX_MODERATOR_PIN", "moderator_pin")

    # shared infrastructure for multi-worker / multi-server deployments (both optional; local development needs neither)
    # postgresql://user:password@host:5432/verioax - accounts, activity, feedback, scan history and preferences in one shared database
    database_url: SecretStr | None = _key("VERIOAX_DATABASE_URL", "DATABASE_URL", "database_url")
    database_pool_size: int = Field(default=10, ge=1, le=100, validation_alias=AliasChoices("VERIOAX_DATABASE_POOL_SIZE", "database_pool_size"))
    # redis://host:6379/0 - rate-limit counters shared by every worker (without it each process counts on its own)
    redis_url: SecretStr | None = _key("VERIOAX_REDIS_URL", "REDIS_URL", "redis_url")
    # key for the personal-data fingerprints (HMAC). Set the same value on every instance; otherwise data_dir/secret.key is used.
    secret_key: SecretStr | None = _key("VERIOAX_SECRET_KEY", "secret_key")

    # request limits ("<count>/<seconds>"), per client
    rate_limit_scan: str = Field(default="30/60", validation_alias=AliasChoices("VERIOAX_RATE_LIMIT_SCAN", "rate_limit_scan"))
    rate_limit_file: str = Field(default="10/60", validation_alias=AliasChoices("VERIOAX_RATE_LIMIT_FILE", "rate_limit_file"))
    rate_limit_api: str = Field(default="300/60", validation_alias=AliasChoices("VERIOAX_RATE_LIMIT_API", "rate_limit_api"))
    rate_limit_ui_scan: str = Field(default="20/60", validation_alias=AliasChoices("VERIOAX_RATE_LIMIT_UI_SCAN", "rate_limit_ui_scan"))
    # reverse proxies whose X-Forwarded-For header may be trusted (comma-separated IPs or CIDR ranges); empty = trust none
    trusted_proxies: str = Field(default="", validation_alias=AliasChoices("VERIOAX_TRUSTED_PROXIES", "trusted_proxies"))
    # bounded work: scans running at once per process, file scans (PDF/OCR/APK) at once, and how long a request may queue
    max_concurrent_scans: int = Field(default=8, ge=1, le=256, validation_alias=AliasChoices("VERIOAX_MAX_CONCURRENT_SCANS", "max_concurrent_scans"))
    max_concurrent_file_scans: int = Field(default=2, ge=1, le=64, validation_alias=AliasChoices("VERIOAX_MAX_CONCURRENT_FILE_SCANS", "max_concurrent_file_scans"))
    scan_queue_timeout_s: float = Field(default=20.0, ge=0.5, le=300, validation_alias=AliasChoices("VERIOAX_SCAN_QUEUE_TIMEOUT_S", "scan_queue_timeout_s"))

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


def api_token_path(settings: Settings) -> Path:
    return Path(settings.data_dir) / "api.token"


def resolve_api_token(settings: Settings | None = None, *, create: bool = False) -> str | None:
    """The API's bearer token: TRUSTGUARD_API_TOKEN, or the token file in the data directory.

    With ``create`` (the API at start-up) a random token is written there when none is configured, so the API is never
    reachable from other machines without a token. The web app reads the same file when both share the data folder
    (as in docker-compose); the token itself is never printed or logged."""
    import os
    import secrets
    import time
    s = settings or get_settings()
    if s.api_token is not None:
        return s.api_token.get_secret_value()
    path = api_token_path(s)

    def read() -> str | None:
        try:
            tok = path.read_text(encoding="utf-8").strip()
            return tok if len(tok) >= 32 else None
        except OSError:
            return None

    if (tok := read()) or not create:
        return tok
    tok = secrets.token_urlsafe(32)
    for _ in range(40):
        # O_EXCL: when several API workers start together exactly one creates the file and the others read it, so all
        # of them (and the web app) end up with the same token
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if (existing := read()) is not None:
                return existing
            time.sleep(0.05)                        # another worker is still writing it
            continue
        except OSError:
            return tok                              # read-only data directory: the token lives for this process only
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(tok)
        return tok
    # a stale, unreadable or truncated file: replace it atomically
    tmp = path.with_name(f".api.token.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(tok)
    os.replace(tmp, path)
    return tok


def preferences_path(settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    return Path(s.data_dir) / "preferences.json"


def _shared_db(settings: Settings):
    """The shared PostgreSQL database when one is configured: preferences then live there, so every server uses the same ones."""
    if settings.database_url is None:
        return None
    from .db import open_database
    db = open_database(settings, "accounts.sqlite")
    db.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT)")
    return db


def load_preferences(settings: Settings | None = None) -> Preferences:
    s = settings or get_settings()
    db = _shared_db(s)
    if db is not None:
        row = db.one("SELECT value FROM app_settings WHERE key = 'preferences'")
        if row:
            try:
                return Preferences.model_validate_json(row["value"])
            except ValueError:
                pass
        return Preferences()
    p = preferences_path(s)
    if p.exists():
        try:
            return Preferences.model_validate_json(p.read_text(encoding="utf-8"))
        except ValueError:
            pass                                 # corrupt or outdated file: fall back to defaults
    return Preferences()


def save_preferences(prefs: Preferences, settings: Settings | None = None) -> Path | str:
    s = settings or get_settings()
    db = _shared_db(s)
    if db is not None:
        from datetime import datetime, timezone
        db.execute("INSERT INTO app_settings (key, value, updated_at) VALUES ('preferences', ?, ?) "
                   "ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                   (prefs.model_dump_json(), datetime.now(timezone.utc).isoformat(timespec="seconds")))
        return "database"
    p = preferences_path(s)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(prefs.model_dump_json(indent=2), encoding="utf-8")
    tmp.replace(p)                               # atomic: a concurrent reader never sees half a file
    return p
