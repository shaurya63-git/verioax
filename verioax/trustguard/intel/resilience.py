"""Keeps slow or failing outside services (threat-intelligence APIs, the OpenPhish feed, fact checks, RDAP) from slowing
every scan down or being hammered while they are down.

* **Shared HTTP clients** - one connection pool per provider, reused across scans, instead of a new TLS handshake per lookup.
* **Bounded concurrency** - at most ``max_parallel`` calls to one provider at a time from this process; a call that can't
  get a turn quickly is reported as unavailable instead of queuing behind a slow service.
* **Circuit breaker** - after ``threshold`` failures in a row (errors or timeouts) a provider is skipped for
  ``cooldown_s`` seconds, then one trial call decides whether it is back. A skipped lookup is reported as
  ``unavailable`` - never as "not listed" - so a provider outage can never make a link look safer.
* **One retry** for failures that happen before the service has seen the request (connection errors, HTTP 502/503/504),
  with a short random back-off. Read time-outs are not retried: the service is slow, and retrying would double the wait.

Health records hold only counts, timings and exception class names - never a URL, a message or an API key.
"""
from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from ..metrics import REGISTRY

RETRYABLE_STATUS = (502, 503, 504)


class CircuitBreaker:
    def __init__(self, threshold: int = 3, cooldown_s: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self.threshold, self.cooldown_s, self.clock = threshold, cooldown_s, clock
        self._lock = threading.Lock()
        self.failures = 0
        self.opened_at: float | None = None
        self._trial = False

    @property
    def state(self) -> str:
        with self._lock:
            if self.opened_at is None:
                return "closed"
            return "half_open" if self._trial or self.clock() - self.opened_at >= self.cooldown_s else "open"

    def allow(self) -> str | None:
        """'closed' or 'trial' when a call may go ahead, None while the circuit is open."""
        with self._lock:
            if self.opened_at is None:
                return "closed"
            if not self._trial and self.clock() - self.opened_at >= self.cooldown_s:
                self._trial = True                  # exactly one trial call while half-open
                return "trial"
            return None

    def cancel_trial(self) -> None:
        """The trial call never started (no free slot): let the next call try instead."""
        with self._lock:
            self._trial = False

    def success(self) -> None:
        with self._lock:
            self.failures, self.opened_at, self._trial = 0, None, False

    def failure(self) -> None:
        with self._lock:
            self.failures += 1
            if self._trial or self.failures >= self.threshold:
                self.opened_at, self._trial = self.clock(), False

    def retry_in(self) -> float:
        with self._lock:
            return 0.0 if self.opened_at is None else max(0.0, self.cooldown_s - (self.clock() - self.opened_at))


@dataclass
class Guard:
    name: str
    breaker: CircuitBreaker
    sem: threading.BoundedSemaphore
    calls: int = 0
    ok: int = 0
    errors: int = 0
    timeouts: int = 0
    skipped: int = 0
    in_flight: int = 0
    last_error: str = ""                       # exception class name or a short fixed label - never a message
    last_ok_at: str | None = None
    last_failure_at: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def begin(self, wait_s: float) -> str | None:
        """None when the call may go ahead, else why it was skipped ('circuit_open' / 'busy')."""
        permit = self.breaker.allow()
        if permit is None:
            self._skip("circuit_open")
            return "circuit_open"
        if not self.sem.acquire(timeout=wait_s):
            if permit == "trial":
                self.breaker.cancel_trial()
            self._skip("busy")
            return "busy"
        with self._lock:
            self.calls += 1
            self.in_flight += 1
        return None

    def end(self, outcome: str, seconds: float, error: str = "") -> None:
        """outcome: ok / error / timeout."""
        self.sem.release()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            self.in_flight -= 1
            if outcome == "ok":
                self.ok += 1
                self.last_ok_at = now
            else:
                self.errors += outcome == "error"
                self.timeouts += outcome == "timeout"
                self.last_error, self.last_failure_at = error or outcome, now
        (self.breaker.success if outcome == "ok" else self.breaker.failure)()
        REGISTRY.inc("provider_calls_total", provider=self.name, outcome=outcome)
        REGISTRY.observe(f"provider {self.name}", seconds)

    def _skip(self, why: str) -> None:
        with self._lock:
            self.skipped += 1
        REGISTRY.inc("provider_calls_total", provider=self.name, outcome="skipped")
        REGISTRY.inc("provider_skipped_total", provider=self.name, reason=why)

    def health(self) -> dict:
        with self._lock:
            row = {"calls": self.calls, "ok": self.ok, "errors": self.errors, "timeouts": self.timeouts, "skipped": self.skipped,
                   "in_flight": self.in_flight, "last_error": self.last_error, "last_ok_at": self.last_ok_at,
                   "last_failure_at": self.last_failure_at}
        row |= {"circuit": self.breaker.state, "consecutive_failures": self.breaker.failures,
                "retry_in_s": round(self.breaker.retry_in(), 1)}
        lat = REGISTRY.percentiles(f"provider {self.name}")
        row |= {"p50_ms": lat["p50_ms"], "p95_ms": lat["p95_ms"]}
        return row


class Resilience:
    """Per-engine state shared by every IntelHub the engine creates (preferences changes rebuild the hub, not this)."""

    def __init__(self, *, max_parallel: int = 4, threshold: int = 3, cooldown_s: float = 60.0, workers: int = 16,
                 clock: Callable[[], float] = time.monotonic):
        self.max_parallel, self.threshold, self.cooldown_s, self.clock = max_parallel, threshold, cooldown_s, clock
        self._guards: dict[str, Guard] = {}
        self._clients: dict[tuple, httpx.Client] = {}
        self._lock = threading.Lock()
        self._workers = workers
        self._executor: ThreadPoolExecutor | None = None

    def guard(self, name: str) -> Guard:
        with self._lock:
            g = self._guards.get(name)
            if g is None:
                g = self._guards[name] = Guard(name, CircuitBreaker(self.threshold, self.cooldown_s, self.clock),
                                               threading.BoundedSemaphore(self.max_parallel))
            return g

    def client(self, key: tuple, factory: Callable[[], httpx.Client]) -> httpx.Client:
        with self._lock:
            c = self._clients.get(key)
            if c is None or c.is_closed:
                c = self._clients[key] = factory()
            return c

    @property
    def executor(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=self._workers, thread_name_prefix="vx-intel")
            return self._executor

    def health(self) -> dict[str, dict]:
        with self._lock:
            guards = dict(self._guards)
        return {name: g.health() for name, g in sorted(guards.items())}

    def close(self) -> None:
        with self._lock:
            clients, self._clients = list(self._clients.values()), {}
            ex, self._executor = self._executor, None
        for c in clients:
            try:
                c.close()
            except Exception:
                pass
        if ex is not None:
            ex.shutdown(wait=False, cancel_futures=True)


def call_with_retry(fn: Callable[[], object]):
    """Run ``fn`` and retry once - only for failures that happen before the service has seen the request."""
    try:
        return fn()
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError):
        pass
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code not in RETRYABLE_STATUS:
            raise
    time.sleep(0.15 + random.random() * 0.25)
    return fn()


def outcome_of(exc: BaseException) -> str:
    return "timeout" if isinstance(exc, httpx.TimeoutException) else "error"
