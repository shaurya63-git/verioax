"""Reproducible load test for the Verioax API.

Starts a local API in offline mode (threat-intelligence lookups, fact checks and live link visits all off, so no traffic
leaves the machine) on a temporary data folder, runs each Locust scenario at each user count, samples the server's CPU
and memory, checks the server is still healthy after every step, and writes the results.

    pip install locust psutil
    python tests/load/run_load.py                                   # message, url, file at 10/25/50/100 users
    python tests/load/run_load.py --users 10,50 --duration 30 --scenarios message
    python tests/load/run_load.py --database-url postgresql://user:pw@localhost:5432/verioax_load

Results go to load-results/<timestamp>/ (summary.md, results.json and Locust's CSV files). The capacity runs raise the
per-client rate limits (all simulated users share one IP address); a final "abuse" run uses the normal limits and checks
that a burst is answered with HTTP 429s rather than errors or a crash.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import secrets
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
LOCUSTFILE = Path(__file__).with_name("locustfile.py")
CLASSES = {"message": "MessageScanUser", "url": "URLScanUser", "file": "FileScanUser"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, data_dir: Path, token: str, workers: int, database_url: str | None, relaxed: bool, redis_url: str | None = None):
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        env = os.environ | {"TRUSTGUARD_DATA_DIR": str(data_dir), "TRUSTGUARD_API_TOKEN": token, "PYTHONPATH": str(ROOT)}
        env.pop("VERIOAX_REDIS_URL", None)
        if redis_url:
            env["VERIOAX_REDIS_URL"] = redis_url
        if database_url:
            env["VERIOAX_DATABASE_URL"] = database_url
        if relaxed:   # capacity runs: every simulated user comes from 127.0.0.1, so per-client limits would cap the test itself
            env |= {"VERIOAX_RATE_LIMIT_SCAN": "1000000/60", "VERIOAX_RATE_LIMIT_FILE": "1000000/60", "VERIOAX_RATE_LIMIT_API": "1000000/60"}
        self.log = open(data_dir / f"server-{self.port}.log", "w")
        self.proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", str(self.port),
                                      "--workers", str(workers), "--log-level", "warning", "--no-access-log"],
                                     cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        self.headers = {"Authorization": f"Bearer {token}"}

    def wait_ready(self, timeout: float = 60) -> None:
        end = time.time() + timeout
        while time.time() < end:
            try:
                if httpx.get(f"{self.url}/ready", timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            if self.proc.poll() is not None:
                raise RuntimeError("the API exited during start-up - see the server log")
            time.sleep(0.5)
        raise RuntimeError("the API did not become ready")

    def healthy(self) -> bool:
        try:
            return self.proc.poll() is None and httpx.get(f"{self.url}/health", timeout=5).status_code == 200
        except httpx.HTTPError:
            return False

    def stats(self) -> dict:
        try:
            return httpx.get(f"{self.url}/v1/ops/stats", headers=self.headers, timeout=10).json()
        except Exception:
            return {}

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


class Sampler(threading.Thread):
    """CPU (% of one core, summed over the server's processes) and resident memory, once a second."""

    def __init__(self, pid: int):
        super().__init__(daemon=True)
        import psutil
        self.psutil, self.root = psutil, psutil.Process(pid)
        self.cpu: list[float] = []
        self.rss: list[float] = []
        self.stop_event = threading.Event()
        self._known: dict[int, object] = {}

    def _procs(self):
        """The same Process objects every time: cpu_percent() measures the time since the previous call on that object."""
        try:
            current = [self.root] + self.root.children(recursive=True)
        except self.psutil.Error:
            return []
        out = []
        for p in current:
            if p.pid not in self._known:
                self._known[p.pid] = p
                try:
                    p.cpu_percent(None)
                except self.psutil.Error:
                    continue
            out.append(self._known[p.pid])
        return out

    def run(self):
        self._procs()
        while not self.stop_event.wait(1.0):
            cpu = rss = 0.0
            for p in self._procs():
                try:
                    cpu += p.cpu_percent(None)
                    rss += p.memory_info().rss / 1e6
                except self.psutil.Error:
                    pass
            self.cpu.append(cpu)
            self.rss.append(rss)

    def summary(self) -> dict:
        self.stop_event.set()
        self.join(3)
        if not self.cpu:
            return {}
        return {"cpu_avg_pct": round(statistics.mean(self.cpu), 1), "cpu_max_pct": round(max(self.cpu), 1),
                "rss_max_mb": round(max(self.rss), 1)}


def run_locust(server: Server, scenario: str, users: int, duration: int, out: Path, token: str, abuse: bool = False,
               no_wait: bool = False) -> dict:
    prefix = out / f"{scenario}-{users}{'-abuse' if abuse else ''}{'-saturation' if no_wait else ''}"
    env = os.environ | {"VERIOAX_LOAD_TOKEN": token, "VERIOAX_LOAD_ABUSE": "1" if abuse else "0", "VERIOAX_LOAD_NO_WAIT": "1" if no_wait else "0"}
    spawn = max(1, users // 5)
    cmd = [sys.executable, "-m", "locust", "-f", str(LOCUSTFILE), "--headless", "-u", str(users), "-r", str(spawn),
           "-t", f"{duration}s", "--host", server.url, "--csv", str(prefix), "--only-summary", "--stop-timeout", "10", CLASSES[scenario]]
    if not abuse:
        cmd.insert(-1, "--reset-stats")          # measure the steady state, not the ramp-up
    sampler = Sampler(server.proc.pid)
    sampler.start()
    t = time.time()
    done = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    wall = time.time() - t
    res = sampler.summary()
    (prefix.parent / f"{prefix.name}.locust.log").write_text(done.stdout + done.stderr)
    row = _aggregated(Path(f"{prefix}_stats.csv"))
    fails = _failures(Path(f"{prefix}_failures.csv"))
    alive = server.healthy()
    return {"scenario": scenario, "users": users, "duration_s": duration, "wall_s": round(wall, 1), **row, "failures_by_reason": fails,
            **res, "server_alive_after": alive, "abuse": abuse, "saturation": no_wait}


def _aggregated(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open(newline="") as f:
        for r in csv.DictReader(f):
            if r["Name"] == "Aggregated":
                n, failed = int(r["Request Count"]), int(r["Failure Count"])
                return {"requests": n, "failed": failed, "error_rate": round(failed / n, 4) if n else 0.0,
                        "rps": round(_num(r["Requests/s"]), 1), "avg_ms": round(_num(r["Average Response Time"])),
                        "p50_ms": int(_num(r["50%"])), "p95_ms": int(_num(r["95%"])), "p99_ms": int(_num(r["99%"])),
                        "max_ms": round(_num(r["Max Response Time"]))}
    return {}


def _num(v: str | None) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _failures(path: Path) -> dict:
    if not path.is_file():
        return {}
    out: dict[str, int] = {}
    with path.open(newline="") as f:
        for r in csv.DictReader(f):
            out[r["Error"][:80]] = out.get(r["Error"][:80], 0) + int(r["Occurrences"])
    return out


def write_summary(out: Path, meta: dict, rows: list[dict]) -> str:
    L = [f"# Verioax load test - {meta['started']}", "",
         f"- Machine: {meta['cpus']} CPU(s), {meta['ram_gb']} GB RAM; Locust and the API ran on the same machine",
         f"- API: uvicorn, {meta['workers']} worker(s), database: {meta['database']}, rate limits: {meta['rate_limits']}, "
         "offline mode (no outside calls)",
         f"- Each step: {meta['duration']} s after ramp-up (stats reset once all users are running); users wait 0.5-1.5 s between scans", "",
         "| Scenario | Users | Requests | Req/s | p50 ms | p95 ms | p99 ms | Errors | Server CPU avg / max | Server RSS max | Alive after |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if r.get("abuse"):
            continue
        L.append(f"| {r['scenario']}{' (no pause)' if r.get('saturation') else ''} | {r['users']} | {r.get('requests', '-')} | {r.get('rps', '-')} | {r.get('p50_ms', '-')} | {r.get('p95_ms', '-')} | "
                 f"{r.get('p99_ms', '-')} | {r.get('error_rate', 0):.2%} | {r.get('cpu_avg_pct', '-')}% / {r.get('cpu_max_pct', '-')}% | "
                 f"{r.get('rss_max_mb', '-')} MB | {'yes' if r['server_alive_after'] else 'NO'} |")
    abuse = [r for r in rows if r.get("abuse")]
    if abuse:
        a = abuse[0]
        reasons = a.get("failures_by_reason") or {}
        limited = sum(v for k, v in reasons.items() if "429" in k)
        other = {k: v for k, v in reasons.items() if "429" not in k}
        L += ["", "## Deliberate burst (normal rate limits, no pause between requests)", "",
              f"{a['users']} users for {a['duration_s']} s from one address: {a.get('requests', 0)} requests - "
              f"{a.get('requests', 0) - a.get('failed', 0)} answered 200, {limited} refused with HTTP 429 (Retry-After), "
              f"{sum(other.values())} other errors{(' ' + str(other)) if other else ''}. Server alive afterwards: "
              f"{'yes' if a['server_alive_after'] else 'NO'}.", ""]
    text = "\n".join(L) + "\n"
    (out / "summary.md").write_text(text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--users", default="10,25,50,100")
    ap.add_argument("--duration", type=int, default=40, help="seconds per step, after ramp-up")
    ap.add_argument("--scenarios", default="message,url,file")
    ap.add_argument("--workers", type=int, default=max(1, min(4, os.cpu_count() or 1)))
    ap.add_argument("--database-url", default=None, help="PostgreSQL URL (default: SQLite in the temporary data folder)")
    ap.add_argument("--redis-url", default=None, help="Redis URL for shared rate limits (default: per-worker memory)")
    ap.add_argument("--no-abuse", action="store_true", help="skip the deliberate-burst run")
    ap.add_argument("--saturation-users", type=int, default=100,
                    help="users for the no-pause message run that finds the throughput ceiling (0 = skip)")
    ap.add_argument("--skip-matrix", action="store_true", help="run only the saturation and burst runs")
    ap.add_argument("--out", default=str(ROOT / "load-results"))
    a = ap.parse_args()

    import psutil

    from trustguard.config import Preferences, Settings, save_preferences
    out = Path(a.out) / datetime.now().strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    data = Path(tempfile.mkdtemp(prefix="verioax-load-"))
    token = secrets.token_urlsafe(32)
    s = Settings(_env_file=None, data_dir=data, database_url=a.database_url)
    save_preferences(Preferences(network_checks=False, intel_lookups=False, openphish_feed=False, factcheck_lookups=False), s)
    meta = {"started": datetime.now().isoformat(timespec="seconds"), "cpus": os.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 1e9, 1),
            "workers": a.workers, "database": "PostgreSQL" if a.database_url else "SQLite (WAL)", "duration": a.duration,
            "rate_limits": "Redis (shared)" if a.redis_url else "in memory, per worker"}
    rows: list[dict] = []
    try:
        server = Server(data, token, a.workers, a.database_url, relaxed=True, redis_url=a.redis_url)
        try:
            server.wait_ready()
            for scenario in ([] if a.skip_matrix else a.scenarios.split(",")):
                for users in (int(u) for u in a.users.split(",")):
                    r = run_locust(server, scenario, users, a.duration, out, token)
                    rows.append(r)
                    print(json.dumps({k: r.get(k) for k in ("scenario", "users", "requests", "rps", "p50_ms", "p95_ms", "p99_ms", "error_rate",
                                                             "cpu_avg_pct", "rss_max_mb", "server_alive_after")}), flush=True)
            if a.saturation_users:
                r = run_locust(server, "message", a.saturation_users, a.duration, out, token, no_wait=True)
                rows.append(r)
                print(json.dumps({k: r.get(k) for k in ("scenario", "users", "requests", "rps", "p50_ms", "p95_ms", "p99_ms", "error_rate",
                                                         "failures_by_reason", "cpu_avg_pct", "server_alive_after")}), flush=True)
            meta["server_stats"] = {k: v for k, v in server.stats().items() if k in ("requests_total", "error_rate", "scans_total",
                                                                                     "busy_rejections_total", "db_errors_total")}
        finally:
            server.stop()
        if not a.no_abuse:
            server = Server(data, token, a.workers, a.database_url, relaxed=False, redis_url=a.redis_url)
            try:
                server.wait_ready()
                r = run_locust(server, "message", 20, 20, out, token, abuse=True)
                rows.append(r)
                print(json.dumps({k: r.get(k) for k in ("scenario", "users", "requests", "failures_by_reason", "server_alive_after")}), flush=True)
            finally:
                server.stop()
    finally:
        (out / "results.json").write_text(json.dumps({"meta": meta, "runs": rows}, indent=2))
        print(write_summary(out, meta, rows))
        shutil.rmtree(data, ignore_errors=True)
    return 0 if all(r["server_alive_after"] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
