"""Shared fixtures. Tests never touch the network: live checks are off by default and every HTTP call goes through
``httpx.MockTransport`` or injected fakes."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import os  # noqa: E402
import tempfile  # noqa: E402

# Nothing the tests run (including module-level app factories) may write into the repository's data folder.
os.environ["TRUSTGUARD_DATA_DIR"] = tempfile.mkdtemp(prefix="trustguard-tests-")
for _k in ("TRUSTGUARD_API_URL", "TRUSTGUARD_API_TOKEN"):
    os.environ.pop(_k, None)
TEST_PIN = "424242"                     # the real moderator PIN is configured in .env, never in code or tests
os.environ["VERIOAX_MODERATOR_PIN"] = TEST_PIN

from trustguard.config import Preferences, Settings, get_settings, save_preferences  # noqa: E402

get_settings.cache_clear()
from trustguard.engine import TrustGuardEngine  # noqa: E402
from trustguard.storage import ScanStore  # noqa: E402

OFFLINE = dict(network_checks=False, intel_lookups=False, factcheck_lookups=False, openphish_feed=False, llm_explanations=False)

# Components that load preferences from the data directory (the Streamlit app under AppTest, the module-level API app)
# must also run offline: a test must never contact a domain named in a sample message, even if someone registers it.
save_preferences(Preferences(**OFFLINE))


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Settings:
    for var in ("GOOGLE_SAFE_BROWSING_API_KEY", "VIRUSTOTAL_API_KEY", "URLHAUS_AUTH_KEY", "PHISHTANK_APP_KEY", "GOOGLE_FACTCHECK_API_KEY",
                "TRUSTGUARD_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    return Settings(_env_file=None, data_dir=tmp_path / "runtime")


@pytest.fixture
def prefs() -> Preferences:
    return Preferences(**OFFLINE)


@pytest.fixture
def engine(settings, prefs) -> TrustGuardEngine:
    return TrustGuardEngine(settings, prefs, store=ScanStore(Path(settings.data_dir) / "history.sqlite"))


ECHALLAN_SCAM = ("Dear Ravi Kumar, your vehicle MH12AB1234 has a pending e-challan of Rs 590. Pay immediately to avoid licence "
                 "suspension and court proceedings: https://echallan-pay.vip/pay")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Belt and braces: a real outbound connection from a test is a bug (live checks must be faked or switched off)."""
    import socket

    real_connect = socket.socket.connect

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else None
        if host is not None and not (str(host).startswith("127.") or host in ("::1", "localhost")):
            raise RuntimeError(f"test attempted a network connection to {host}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)
