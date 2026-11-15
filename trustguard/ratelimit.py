"""Request rate limits: per client, per scan type, shared across workers when Redis is configured.

* ``MemoryLimiter`` - counters in this process. Fine for one process (local development, a single Streamlit server).
  Memory is bounded: at most ``max_keys`` clients are tracked; the least recently seen are forgotten first.
* ``RedisLimiter`` - counters in Redis (``VERIOAX_REDIS_URL``), so every API worker and every server enforces the same
  budget. If Redis stops answering, the limiter falls back to per-process counting instead of failing requests, and
  the fallback is counted in the metrics (``ratelimit_backend_errors``).

Both use a sliding-window approximation: the count in the current fixed window plus the previous window's count weighted
by how much of it still overlaps. A limit is written "<requests>/<seconds>", e.g. "30/60".
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class Rate:
    limit: int
    window_s: int

    @classmethod
    def parse(cls, spec: str) -> Rate:
        try:
            n, s = str(spec).split("/", 1)
            rate = cls(int(n), int(s))
        except (ValueError, TypeError):
            raise ValueError(f"invalid rate '{spec}' (expected '<requests>/<seconds>', e.g. '30/60')") from None
        if rate.limit < 1 or rate.window_s < 1:
            raise ValueError(f"invalid rate '{spec}'")
        return rate


@dataclass(frozen=True)
class Decision:
    allowed: bool
    remaining: int
    retry_after: int            # seconds until a request would be allowed again (0 when allowed)


def _decide(prev: int, cur: int, rate: Rate, now: float) -> Decision:
    elapsed = (now % rate.window_s) / rate.window_s
    estimate = prev * (1 - elapsed) + cur
    if estimate > rate.limit:
        retry = max(1, math.ceil(rate.window_s * (1 - elapsed)))
        return Decision(False, 0, retry)
    return Decision(True, max(0, int(rate.limit - estimate)), 0)


class MemoryLimiter:
    backend = "memory"

    def __init__(self, max_keys: int = 20_000):
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self._windows: OrderedDict[str, tuple[int, int, int]] = OrderedDict()     # key -> (window index, count, previous count)

    def hit(self, key: str, rate: Rate, now: float | None = None) -> Decision:
        now = time.time() if now is None else now
        idx = int(now // rate.window_s)
        k = f"{key}|{rate.limit}/{rate.window_s}"
        with self._lock:
            w, cur, prev = self._windows.get(k, (idx, 0, 0))
            if w != idx:
                prev, cur = (cur if w == idx - 1 else 0), 0
            d = _decide(prev, cur + 1, rate, now)
            if d.allowed:
                cur += 1
            self._windows[k] = (idx, cur, prev)
            self._windows.move_to_end(k)
            while len(self._windows) > self.max_keys:
                self._windows.popitem(last=False)
        return d

    def size(self) -> int:
        return len(self._windows)


class RedisLimiter:
    backend = "redis"

    def __init__(self, url: str, prefix: str = "vx:rl:", fallback: MemoryLimiter | None = None, on_error=None):
        import redis  # optional dependency (the 'scale' extra)
        self._r = redis.Redis.from_url(url, socket_timeout=0.25, socket_connect_timeout=0.25)
        self.prefix = prefix
        self._salt = hashlib.sha256(f"verioax-rl|{url}".encode()).digest()[:16]     # same on every worker sharing this Redis
        self.fallback = fallback or MemoryLimiter()
        self.on_error = on_error

    def hit(self, key: str, rate: Rate, now: float | None = None) -> Decision:
        now = time.time() if now is None else now
        idx = int(now // rate.window_s)
        # keys name a client (an IP address or an account id): store only a keyed hash of it in Redis
        base = f"{self.prefix}{hashlib.blake2b(key.encode(), digest_size=12, key=self._salt).hexdigest()}|{rate.limit}/{rate.window_s}"
        try:
            pipe = self._r.pipeline()
            pipe.incr(f"{base}:{idx}")
            pipe.expire(f"{base}:{idx}", rate.window_s * 2)
            pipe.get(f"{base}:{idx - 1}")
            cur, _, prev = pipe.execute()
        except Exception as exc:                            # Redis down: keep enforcing limits locally
            if self.on_error:
                self.on_error(type(exc).__name__)
            return self.fallback.hit(key, rate, now)
        return _decide(int(prev or 0), int(cur), rate, now)


def make_limiter(redis_url: str | None, on_error=None):
    if redis_url:
        try:
            return RedisLimiter(redis_url, on_error=on_error)
        except ImportError:
            pass
    return MemoryLimiter()


# ---------------------------------------------------------------------------------------------- who is the client?
def parse_networks(spec: str) -> list[ipaddress._BaseNetwork]:
    nets = []
    for part in (spec or "").split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


def _in(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def client_ip(peer: str | None, forwarded_for: str | None, trusted) -> str:
    """The real client address. X-Forwarded-For is believed only when the direct peer is a trusted proxy, and then the
    right-most address that isn't itself a trusted proxy is used (left-most entries can be forged by the client)."""
    peer = peer or "unknown"
    if not forwarded_for or not trusted or not _in(peer, trusted):
        return peer
    for hop in reversed([h.strip() for h in forwarded_for.split(",") if h.strip()][-20:]):
        try:
            addr = str(ipaddress.ip_address(hop.split("%")[0]))
        except ValueError:
            return peer                      # garbage in the header: never a rate-limit key of its own
        if not _in(addr, trusted):
            return addr
    return peer


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return ip in ("localhost", "testclient")
