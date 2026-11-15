# Load testing

`tests/load/` has a reproducible load test built on [Locust](https://locust.io).

```bash
pip install locust psutil
python tests/load/run_load.py                       # message, link and file scans at 10 / 25 / 50 / 100 users
python tests/load/run_load.py --users 10,50 --scenarios message --duration 30
python tests/load/run_load.py --workers 4 --database-url postgresql://user:pw@localhost:5432/verioax_load
```

The runner does the following:

1. Starts its own API (`uvicorn api.main:app --workers N`) on a temporary data folder, in **offline mode**:
   - no threat-intelligence lookups
   - no fact checks
   - no live link visits

   No load-test traffic leaves the machine, and no third-party service or real phishing site is contacted. The inputs
   are synthetic messages, links, a text file and the sample PDF.
2. Runs each scenario at each user count.
   - Simulated users wait 0.5–1.5 s between scans, like people do.
   - Statistics are reset once every user is running, so ramp-up doesn't distort them.
   - Scans are spread over 200 account ids.
3. Samples the server's CPU (summed over all its processes; 100% = one core) and resident memory every second.
4. Checks `/health` after every step, to answer "did it crash?".
5. Runs a **no-pause saturation step**: 100 users who send the next scan as soon as the previous one returns. This finds
   the throughput ceiling and shows what overload looks like.
6. Restarts the API with the **normal rate limits** and sends a deliberate burst: 20 users, no pause, one address. A
   burst like that must be answered with HTTP 429, not errors or a crash.

The capacity steps raise the per-client limits, because every simulated user comes from 127.0.0.1. With normal limits
they would measure the rate limiter, not the server.

Results go to `load-results/<timestamp>/`: `summary.md`, `results.json` and Locust's CSV files.

To run the scenarios by hand against an API you started yourself:
`locust -f tests/load/locustfile.py --host http://127.0.0.1:8000 MessageScanUser`. Set `VERIOAX_LOAD_TOKEN` to its
token.

Never point it at a server you don't own.

## Results on the development machine (15 Nov 2026)

These numbers were **measured**, not estimated. They come from one cloud VM with 2 vCPUs (Intel Xeon 2.1 GHz) and 8 GB
RAM. Locust and the API shared the machine, so the generator took CPU away from the server. The API ran 2 uvicorn workers
in offline mode. Each step ran 40 s after ramp-up (30 s for the PostgreSQL and saturation runs).

**SQLite (WAL), in-memory rate limits:**

| Scenario | Users | Requests | Req/s | p50 | p95 | p99 | Errors | Server CPU avg / max | Server memory |
|---|---|---|---|---|---|---|---|---|---|
| message | 10 | 342 | 9.8 | 9 ms | 16 ms | 20 ms | 0 | 8% / 19% | 224 MB |
| message | 25 | 861 | 24.6 | 9 ms | 18 ms | 25 ms | 0 | 17% / 22% | 227 MB |
| message | 50 | 1,722 | 49.2 | 11 ms | 26 ms | 34 ms | 0 | 35% / 43% | 232 MB |
| message | 100 | 3,431 | 97.9 | 14 ms | 42 ms | 66 ms | 0 | 66% / 80% | 241 MB |
| link (offline checks) | 10 | 344 | 9.8 | 8 ms | 13 ms | 17 ms | 0 | 6% / 9% | 241 MB |
| link | 25 | 877 | 25.1 | 8 ms | 15 ms | 21 ms | 0 | 14% / 19% | 242 MB |
| link | 50 | 1,767 | 50.5 | 8 ms | 20 ms | 32 ms | 0 | 28% / 35% | 244 MB |
| link | 100 | 3,484 | 99.5 | 9 ms | 24 ms | 42 ms | 0 | 51% / 62% | 248 MB |
| file (text + PDF upload) | 10 | 341 | 9.7 | 28 ms | 70 ms | 110 ms | 0 | 23% / 41% | 342 MB |
| file | 25 | 835 | 23.8 | 29 ms | 82 ms | 120 ms | 0 | 48% / 77% | 436 MB |
| file | 50 | 1,636 | 45.4 | 84 ms | 270 ms | 370 ms | 0 | 99% / 120% | 447 MB |
| file | 100 | 2,690 | 74.6 | 320 ms | 640 ms | 860 ms | 0 | 160% / 180% | 463 MB |

CPU is summed over the server's processes: 100% is one core, and this machine has two.

**Saturation (100 users, no pause, message scans, Redis rate limits):** 191.5 req/s. Latency p50 470 ms, p95 980 ms,
p99 1.6 s. No errors, no 503s. Server CPU 131% average. This is the throughput ceiling of this machine with Locust
running on it. Above it, requests wait for a scan slot instead of failing.

**PostgreSQL 16 on the same machine, Redis rate limits:**

| Scenario | Users | Req/s | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|---|
| message | 50 | 49.3 | 15 ms | 35 ms | 63 ms | 0 |
| message | 100 | 97.9 | 22 ms | 73 ms | 110 ms | 0 |
| file | 50 | 45.9 | 74 ms | 230 ms | 300 ms | 0 |
| file | 100 | 61.0 | 650 ms | 980 ms | 1.4 s | 0 |

PostgreSQL itself also ran on the two cores, which shows in the file run at 100 users.

**Deliberate burst** (20 users, no pause, one address, normal limits, 20 s):

| Rate limits | Requests | Answered 200 | Refused with 429 | Other errors | Server afterwards |
|---|---|---|---|---|---|
| in memory | 28,772 | 64 | 28,708 | 0 | healthy |
| Redis | 27,960 | 30 | 27,930 | 0 | healthy |

The scan limit is 30 per minute per client. With in-memory limits each of the 2 workers counted separately (2 × ~30 =
64). With Redis the limit was shared exactly (30). This is why multi-worker deployments should set `VERIOAX_REDIS_URL`.

After every step the server answered `/health`. Locust counted no failed request in any capacity step, so no
database error, busy rejection (503) or crash reached a client.

### What this does and doesn't show

- **Shown:** on this 2-vCPU machine, 100 simultaneous users who scan about once a second are served without errors. p95
  stays under 75 ms for messages and links (SQLite and PostgreSQL) and under 1 s for file uploads. Overload slows
  answers down; it doesn't crash the server or lose data.
- **Not shown:**
  - Live link checks and threat-intelligence lookups were off on purpose. With them on, a link scan takes as long as the
    slowest outside service, up to the per-provider deadline. The resilience features (circuit breakers, parallel
    lookups, deadlines) are covered by unit tests with fake providers (`tests/test_resilience.py`), not by this load
    test.
  - OCR of images and APK uploads were not part of the file mix.
  - The Streamlit web app was not load-tested. It runs the same engine, but each browser session also holds its own
    Streamlit state.
  - No claim is made for any traffic level beyond the measured one, or for other hardware.

### Budgets

Measured on this machine and used as regression budgets:

| Scenario | 100 users, p95 | Error rate |
|---|---|---|
| message | ≤ 100 ms | 0 |
| link (offline) | ≤ 100 ms | 0 |
| file (text and small PDF) | ≤ 1.5 s | 0 |

Larger PDFs, OCR and APKs take longer per scan. The 2 file slots per process keep them from starving message scans.
