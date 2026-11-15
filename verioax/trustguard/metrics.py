"""In-process operational metrics: request counts and latency percentiles, scan throughput, errors, rate-limit
rejections, database failures, threat-intelligence timeouts, worker saturation, CPU and memory.

Nothing here ever holds message text, links, file names, account names, API keys or personal data: labels are fixed
route templates ("/v1/scan/message"), scan types, verdict levels, provider names and exception class names.

Exposed as Prometheus text on ``/metrics`` and as JSON on ``/v1/ops/stats`` (both behind the API token), and on the
moderators' overview page. Each process keeps its own numbers; with several workers, scrape each one (or use the
Prometheus multiprocess setup) - the figures are per worker.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
_RESERVOIR = 4096                     # latest samples per series kept for percentiles


class Registry:
    def __init__(self):
        self._lock = threading.Lock()
        self.started = time.time()
        self.counters: dict[tuple[str, tuple], float] = defaultdict(float)
        self.gauges: dict[str, float] = defaultdict(float)
        self._samples: dict[str, deque] = defaultdict(lambda: deque(maxlen=_RESERVOIR))
        self._buckets: dict[str, list[int]] = defaultdict(lambda: [0] * (len(_BUCKETS) + 1))
        self._sums: dict[str, float] = defaultdict(float)

    # ------------------------------------------------------------------ recording
    def inc(self, name: str, n: float = 1.0, **labels) -> None:
        key = (name, tuple(sorted((k, str(v)) for k, v in labels.items())))
        with self._lock:
            self.counters[key] += n

    def gauge_add(self, name: str, n: float) -> None:
        with self._lock:
            self.gauges[name] += n

    def observe(self, series: str, seconds: float) -> None:
        with self._lock:
            self._samples[series].append(seconds)
            self._sums[series] += seconds
            b = self._buckets[series]
            for i, edge in enumerate(_BUCKETS):
                if seconds <= edge:
                    b[i] += 1
                    break
            else:
                b[-1] += 1

    # ------------------------------------------------------------------ reading
    def percentiles(self, series: str) -> dict[str, float | int]:
        with self._lock:
            data = sorted(self._samples.get(series, ()))
            count = sum(self._buckets[series]) if series in self._buckets else 0
            total = self._sums.get(series, 0.0)
        if not data:
            return {"count": count, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}

        def pct(p: float) -> float:
            return round(data[min(len(data) - 1, int(round(p * (len(data) - 1))))] * 1000, 1)
        return {"count": count, "mean_ms": round(total / max(count, 1) * 1000, 1), "p50_ms": pct(0.50), "p95_ms": pct(0.95), "p99_ms": pct(0.99)}

    def counter_total(self, name: str, **match) -> float:
        with self._lock:
            return sum(v for (n, labels), v in self.counters.items() if n == name and all((k, str(val)) in labels for k, val in match.items()))

    def snapshot(self) -> dict:
        proc = process_stats()
        with self._lock:
            counters = [{"name": n, "labels": dict(lbl), "value": v} for (n, lbl), v in sorted(self.counters.items())]
            gauges = dict(self.gauges)
            series = list(self._samples)
        requests = self.counter_total("requests_total")
        errors = self.counter_total("requests_total", outcome="error")
        uptime = time.time() - self.started
        return {
            "uptime_s": round(uptime, 1),
            "requests_total": requests,
            "error_rate": round(errors / requests, 4) if requests else 0.0,
            "scans_total": self.counter_total("scans_total"),
            "scans_per_minute": round(self.counter_total("scans_total") / max(uptime / 60, 1e-9), 2),
            "rate_limited_total": self.counter_total("rate_limited_total"),
            "busy_rejections_total": self.counter_total("busy_total"),
            "db_errors_total": self.counter_total("db_errors_total"),
            "provider_failures_total": self.counter_total("provider_calls_total", outcome="error")
                                       + self.counter_total("provider_calls_total", outcome="timeout"),
            "latency": {s: self.percentiles(s) for s in sorted(series)},
            "gauges": gauges,
            "process": proc,
            "counters": counters,
        }

    def prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            for (name, labels), v in sorted(self.counters.items()):
                lab = ",".join(f'{k}="{_esc(val)}"' for k, val in labels)
                lines.append(f"verioax_{name}{{{lab}}} {v:g}" if lab else f"verioax_{name} {v:g}")
            for name, v in sorted(self.gauges.items()):
                lines.append(f"verioax_{name} {v:g}")
            for series, b in sorted(self._buckets.items()):
                cum = 0
                for edge, n in zip(_BUCKETS, b, strict=False):
                    cum += n
                    lines.append(f'verioax_duration_seconds_bucket{{series="{_esc(series)}",le="{edge}"}} {cum}')
                cum += b[-1]
                lines.append(f'verioax_duration_seconds_bucket{{series="{_esc(series)}",le="+Inf"}} {cum}')
                lines.append(f'verioax_duration_seconds_sum{{series="{_esc(series)}"}} {self._sums[series]:.6f}')
                lines.append(f'verioax_duration_seconds_count{{series="{_esc(series)}"}} {cum}')
        for k, v in process_stats().items():
            if isinstance(v, (int, float)):
                lines.append(f"verioax_process_{k} {v:g}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self.counters.clear()
            self.gauges.clear()
            self._samples.clear()
            self._buckets.clear()
            self._sums.clear()
            self.started = time.time()


def _esc(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def process_stats() -> dict[str, float]:
    t = os.times()
    out = {"cpu_seconds": round(t.user + t.system, 2), "threads": threading.active_count()}
    try:                                                     # current resident memory (Linux)
        with open("/proc/self/statm", encoding="ascii") as f:
            out["rss_mb"] = round(int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1e6, 1)
    except (OSError, ValueError, AttributeError):
        try:                                                 # macOS / other Unix: peak memory; Windows has no 'resource' module
            import resource
            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            out["max_rss_mb"] = round(peak / (1e6 if os.uname().sysname == "Darwin" else 1e3), 1)
        except Exception:
            pass
    return out


REGISTRY = Registry()


class timed:
    """``with timed("scan.message"): ...`` records the duration in the latency series."""

    def __init__(self, series: str):
        self.series = series

    def __enter__(self):
        self.t = time.perf_counter()
        return self

    def __exit__(self, *exc):
        REGISTRY.observe(self.series, time.perf_counter() - self.t)
        return False
