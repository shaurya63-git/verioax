"""Rate limiting: the sliding-window decision, bounded memory, client identity behind proxies, the Redis backend
(shared across workers; set VERIOAX_TEST_REDIS_URL to run those tests) and its fallback when Redis is down."""
import os

import pytest

from trustguard.metrics import REGISTRY, Registry
from trustguard.ratelimit import MemoryLimiter, Rate, RedisLimiter, client_ip, is_loopback, make_limiter, parse_networks

REDIS = os.environ.get("VERIOAX_TEST_REDIS_URL")


def test_rate_parse_and_validation():
    r = Rate.parse("30/60")
    assert (r.limit, r.window_s) == (30, 60)
    for bad in ("", "30", "0/60", "30/0", "x/y", "-1/5"):
        with pytest.raises(ValueError):
            Rate.parse(bad)


def test_sliding_window_allows_the_limit_then_refuses_with_a_wait_time():
    lim, rate = MemoryLimiter(), Rate(3, 60)
    assert [lim.hit("k", rate, now=1000.0).allowed for _ in range(4)] == [True, True, True, False]
    d = lim.hit("k", rate, now=1001.0)
    assert not d.allowed and 1 <= d.retry_after <= 60
    assert lim.hit("other", rate, now=1001.0).allowed                         # keys are independent
    assert lim.hit("k", rate, now=1000.0 + 125).allowed                        # two windows later: allowed again


def test_previous_window_still_counts_so_bursts_at_the_boundary_are_limited():
    lim, rate = MemoryLimiter(), Rate(10, 60)
    for _ in range(10):
        assert lim.hit("k", rate, now=119.0).allowed                           # end of window 1
    assert not lim.hit("k", rate, now=121.0).allowed                           # start of window 2: still ~all of window 1


def test_memory_limiter_is_bounded():
    lim = MemoryLimiter(max_keys=100)
    for i in range(1000):
        lim.hit(f"ip-{i}", Rate(5, 60), now=10.0)
    assert lim.size() <= 100


def test_forwarded_for_is_trusted_only_from_configured_proxies():
    nets = parse_networks("10.0.0.0/8, 192.168.1.5")
    assert client_ip("10.1.2.3", "203.0.113.7, 10.9.9.9", nets) == "203.0.113.7"     # through our proxy: the real client
    assert client_ip("198.51.100.4", "1.2.3.4", nets) == "198.51.100.4"              # anyone else can't spoof an address
    assert client_ip("192.168.1.5", "garbage", nets) == "192.168.1.5"
    assert client_ip(None, None, nets) == "unknown"
    assert is_loopback("127.0.0.1") and is_loopback("::1") and not is_loopback("203.0.113.7")


def test_metrics_registry_counts_and_percentiles_without_labels_from_input():
    reg = Registry()
    for ms in range(1, 101):
        reg.observe("scan.message", ms / 1000)
    p = reg.percentiles("scan.message")
    assert p["count"] == 100 and 45 <= p["p50_ms"] <= 55 and 90 <= p["p95_ms"] <= 100 and p["p99_ms"] >= p["p95_ms"]
    reg.inc("requests_total", route="/v1/scan/message", status=200, outcome="ok")
    assert 'verioax_requests_total{outcome="ok",route="/v1/scan/message",status="200"} 1' in reg.prometheus()
    assert REGISTRY is not reg


def test_redis_down_falls_back_to_local_limits():
    errors = []
    lim = make_limiter("redis://127.0.0.1:1/0", on_error=errors.append)        # nothing listens on port 1
    if not isinstance(lim, RedisLimiter):
        pytest.skip("the redis package is not installed")
    rate = Rate(2, 60)
    assert [lim.hit("k", rate).allowed for _ in range(3)] == [True, True, False]
    assert errors and all(isinstance(e, str) and e for e in errors)          # exception class names only


@pytest.mark.skipif(not REDIS, reason="set VERIOAX_TEST_REDIS_URL to run the Redis tests")
def test_redis_limits_are_shared_between_workers():
    import redis
    redis.Redis.from_url(REDIS).flushdb()
    a, b = RedisLimiter(REDIS), RedisLimiter(REDIS)                            # two API workers
    rate = Rate(4, 60)
    got = [(a if i % 2 else b).hit("scan:203.0.113.7", rate).allowed for i in range(6)]
    assert got == [True, True, True, True, False, False]


@pytest.mark.skipif(not REDIS, reason="set VERIOAX_TEST_REDIS_URL to run the Redis tests")
def test_redis_keys_hold_no_ip_addresses_or_account_ids():
    import redis
    r = redis.Redis.from_url(REDIS)
    r.flushdb()
    RedisLimiter(REDIS).hit("scan:203.0.113.7", Rate(5, 60))
    RedisLimiter(REDIS).hit("ui-scan:user:42", Rate(5, 60))
    keys = [k.decode() for k in r.keys("*")]
    assert keys and not any("203.0.113.7" in k or "user:42" in k for k in keys)
    assert all(r.ttl(k) > 0 for k in keys)                                     # everything expires
