# Deployment

Verioax runs in three shapes. Pick the smallest one that fits.

| Shape | Who it is for | Storage | Rate limits |
|---|---|---|---|
| **Local** - `streamlit run app/streamlit_app.py` | one person, one machine | SQLite files in `TRUSTGUARD_DATA_DIR` | per process |
| **Docker, one machine** - `docker compose up --build` | a small group on one server | SQLite in a shared Docker volume | per API worker |
| **Several workers or servers** - `docker-compose.prod.yml` | many users at once | one shared PostgreSQL database | shared in Redis |

Nothing needs a third-party API key. Without keys Verioax uses its own rules and its built-in list of known scam domains.

## Local

```bash
pip install -r requirements.txt
cp .env.example .env              # optional: API keys, VERIOAX_MODERATOR_PIN
streamlit run app/streamlit_app.py
# the REST API, if you want it too:
uvicorn api.main:app --port 8000
```

SQLite runs in WAL mode with a busy timeout and one connection per thread, so the web app and the API can use the same
data folder at the same time.

## Docker on one machine

```bash
cp .env.example .env
docker compose up --build
```

- Web app: http://localhost:8501. API docs: http://localhost:8000/docs.
- Both ports are bound to 127.0.0.1.
- The API runs two workers.
- Both containers share the `trustguard-data` volume. Accounts, the activity log, scan history, preferences and the API
  token all live there, so they survive a rebuild.

## Several workers or servers

Separate processes need one shared database and shared rate-limit counters. Otherwise each process has its own accounts
and history and its own limits. `docker-compose.prod.yml` adds both:

```bash
cp .env.example .env
# in .env set at least:
#   TRUSTGUARD_API_TOKEN=<32+ random characters>      python -c "import secrets; print(secrets.token_urlsafe(32))"
#   POSTGRES_PASSWORD=<letters and digits>
#   VERIOAX_MODERATOR_PIN=<6 digits>
#   VERIOAX_SECRET_KEY=<any long random string>
#   VERIOAX_API_WORKERS=4                             (optional)
docker compose -f docker-compose.prod.yml up --build -d
```

Without Docker, install the extras and set the same variables:

```bash
pip install "psycopg[binary]" psycopg-pool redis      # included in requirements.txt
export VERIOAX_DATABASE_URL=postgresql://verioax:PASSWORD@db-host:5432/verioax
export VERIOAX_REDIS_URL=redis://redis-host:6379/0
export TRUSTGUARD_API_TOKEN=...   VERIOAX_SECRET_KEY=...
uvicorn api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Run the web app with the same `VERIOAX_DATABASE_URL`, so every instance shares accounts and the activity log. Add
`TRUSTGUARD_API_URL` and the token if it should send scans to the API.

### Put a reverse proxy in front

Terminate TLS in nginx, Caddy or a cloud load balancer. Set `VERIOAX_TRUSTED_PROXIES` to the proxy's address or network,
for example `10.0.0.0/8`.

- `X-Forwarded-For` is honoured **only** from those addresses, so per-client limits see the real client.
- Nobody else can fake an address with that header.
- A request that arrives through a proxy never gets the "same machine" exemption from the API token.

## API access

| Situation | What the API accepts |
|---|---|
| `TRUSTGUARD_API_TOKEN` set | Only requests with `Authorization: Bearer <token>`, local ones included. |
| No token set | It generates one on first start and saves it as `api.token` (owner-only) in the data folder. Direct requests from the same machine (127.0.0.1 or ::1, no proxy headers) are accepted without it; everything else needs it. |

- `X-Verioax-Owner: <account id>` makes the API act for one consumer account: scans are stored under that account, and
  listing, reading or deleting scans is limited to it. The header is honoured **only on authenticated requests**. An
  unauthenticated request that sends it gets 401, so nobody can read or write another person's history.
- `/health` (liveness) and `/ready` (the database answers) are open for load balancers. They report only status, the
  database type and a ping time. `/metrics`, `/v1/ops/stats` and every `/v1` route need the token under the rules above.

## Limits and overload behaviour

| Setting | Default | Effect |
|---|---|---|
| `VERIOAX_RATE_LIMIT_SCAN` | `30/60` | message and link scans per client per minute |
| `VERIOAX_RATE_LIMIT_FILE` | `10/60` | file uploads per client per minute |
| `VERIOAX_RATE_LIMIT_API` | `300/60` | all `/v1` calls per client per minute |
| `VERIOAX_RATE_LIMIT_UI_SCAN` | `20/60` | scans per signed-in account in the web app |
| `VERIOAX_MAX_CONCURRENT_SCANS` | `8` | scans running at once in one process |
| `VERIOAX_MAX_CONCURRENT_FILE_SCANS` | `2` | file scans (PDF, OCR, APK) at once in one process |
| `VERIOAX_SCAN_QUEUE_TIMEOUT_S` | `20` | how long a request waits for a free slot |

**Over a rate limit:** HTTP 429 with `Retry-After`. Limits use a sliding window. In memory they are bounded (least
recently seen clients are dropped first). With Redis they are shared by every worker. The Redis keys hold a keyed hash of
the client, never an IP address, and they expire. If Redis is unreachable, each worker falls back to its own in-memory
limits and counts the error in the metrics.

**Server busy:** a scan that can't get a slot within the queue timeout gets HTTP 503 with `Retry-After: 5`.

**Other rules:**

- Uploads over 15 MB (APKs: 50 MB) get HTTP 413 before they are parsed.
- Every scan accepts an `Idempotency-Key` header. Retrying with the same key returns the first result instead of storing
  a second scan. The web app's API client does this automatically when it retries.

## Database migrations and backups

Schemas are versioned in a `schema_migrations` table and upgraded automatically on start. Before upgrading an existing
SQLite file, Verioax copies it next to the original as `<file>.pre-<component>-v<N>-<timestamp>.bak`. No migration
deletes data.

```bash
python -m trustguard.dbtools check                 # which database, schema versions, row counts
python -m trustguard.dbtools backup                # consistent copies of the SQLite files into <data>/backups
python -m trustguard.dbtools prune-activity        # back up, then remove activity entries of retired event types
python -m trustguard.dbtools copy-to-postgres --to postgresql://verioax:PASSWORD@host:5432/verioax
```

`copy-to-postgres` moves an existing installation's accounts, activity, feedback, scan history and preferences into
PostgreSQL. It keeps ids, so links and references stay valid. It refuses to write into a database that already has data
unless you pass `--force`.

### Upgrading an installation from before this version

Older databases recorded page views, sign-outs and failed sign-ins in the activity table. The upgrade keeps those rows
but hides them: the activity log shows only sign-ins, scans and feedback. `prune-activity` removes them for good, after
a backup.

Failed sign-in counters and lockouts now live on the account itself and in a separate `security_events` table, never in
the activity log.

## Monitoring

`/metrics` gives Prometheus text and `/v1/ops/stats` gives JSON. Both need the token. They report:

- request counts by route and status, error rate, and p50, p95 and p99 latency per route and scan type
- scans per minute, rate-limit and busy rejections, database errors
- per-provider calls, failures, timeouts and circuit state
- CPU and memory

They hold no message text, links, file names, account names or keys. Each worker keeps its own figures, so scrape every
worker. Moderators see the same figures under **Moderator overview → Service health**.

## Threat-intelligence providers under load

Each provider has:

- a shared connection pool
- at most 4 calls at once per process
- a timeout (`TRUSTGUARD_FETCH_TIMEOUT_S`)
- one retry, only for connection failures and HTTP 502/503/504

After 3 failures in a row, a provider is skipped for 60 seconds. Then one trial call decides whether it is back. Providers
are asked in parallel, so a slow provider costs a scan at most its own deadline.

A provider that is down, skipped or slow is reported as **unavailable** or **no answer in time**. It is never reported
as "not listed", and an unreachable link never lowers the risk.
