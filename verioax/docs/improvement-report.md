# Verioax improvement report (November 2026)

This report covers the changes made after commit `2efd2e9` ("Accounts, moderator UI, feedback, stronger hoax
detection"), following the master improvement prompt. All numbers below were measured in this round. Where something
was not measured or not done, the report says so.

**Baseline before any change:**

- 229 tests passing
- ruff clean
- the development set at 1.0, which hid how brittle the rules were

The audit notes are summarised under A, C, E and F.

---

## A. Detection improvements

### What was wrong

**1. Detection was a list of phrases.**

- There was no concept of:
  - a crypto or gambling context
  - a reward just for registering
  - an instant-withdrawal claim, or a "no deposit" bonus
  - a promo code
  - a post that "will be deleted"
  - a first-person "I launched my own…" announcement
  - an unverified partnership
- There was no amount parsing ($, USDT, BTC, lakh).
- There was no wallet-connect or seed-phrase rule.

**2. No normalisation.** Spaced letters (`g i v i n g`), leetspeak (`withdr@w`), zero-width characters and `nyxwin dot
com` all slipped through.

**3. Verdicts rested on two or three phrases.** On the code in the repository, the casino post scored **HIGH 54**:
`giveaway_link` + "claim your reward" + "giving away" + urgency + http. That was just over the line. Other results:

| Input | Old result |
|---|---|
| The same post, conservative sensitivity | MEDIUM 52 |
| The same post, the version before that | MEDIUM 30 |
| A reworded copy | INCONCLUSIVE 14 |
| "nyxwin dot com" | LOW 15 |
| Hinglish | INCONCLUSIVE 10 |
| Airdrop + seed phrase | INCONCLUSIVE 5 |

That is consistent with the LOW you saw.

**4. Debunk handling was narrow.** It did not cover quoted or reported speech, plural forms or news-style warnings.

### What was added

**Evasion-resistant matching** (`trustguard/scam/normalize.py`)

- Every indicator runs on the original text and on a normalised copy. The copy has:
  - zero-width characters removed
  - NFKC folding and homoglyph folding
  - leetspeak undone
  - spaced letters joined
  - "dot com" read as a domain
- A source-offset map points every match back to the original fragment.
- Normalisation can add matches, never remove them.

**Money parsing** (`trustguard/scam/money.py`)

- Formats: ₹, Rs, rupaye, lakh, crore, $, €, £, crypto tickers, Indian digit grouping, `$4.200`.
- A rough rupee rate is used **only** to decide "unusually large" (≥ ₹5,000).

**22 new text indicators** (36 → 58):

- reward and giveaway: `reward_offer`, `everyone_reward`, `registration_reward`, `instant_withdrawal`, `no_deposit_bonus`,
  `vanishing_post`
- persona and context: `self_launch_claim`, `partnership_claim`, `crypto_context`, `gambling_context`, `promo_code`
- crypto: `crypto_send_to_receive`, `wallet_connect_lure`, `seed_phrase_request`, `pump_hype`
- payment and support: `accidental_transfer`, `account_alert_lure`, `tech_support_scare`, `refund_lure`,
  `bank_details_request`, `chat_handle`
- other: `lottery_mention`

There are Hindi and Hinglish wordings where they matter. `unrealistic_reward` is derived from the parsed amount.

**10 new combination rules** (16 → 26). These are high · strong unless noted:

- crypto / casino bonus
- cash for signing up
- crypto or gambling promotion (medium · weak)
- reward claimed on an outside site (low · weak, explanatory)
- wallet drainer
- fake customer care on a mobile number
- account warning + callback number
- "sent by mistake" + approve request
- fake security alert + support number
- refund + details request

**Independent evidence families and a complete-pattern floor** (`trustguard/risk.py`)

- A strong, high or critical combination built from **three or more independent families** is at least HIGH.
- For example: reward + destination + crypto/casino context + registration + instant withdrawal + scarcity.
- This lets the message itself justify HIGH without claiming the site is malicious.
- Weak findings alone are still capped at MEDIUM.

**Two new categories** (`CRYPTO_GAMBLING`, `MALICIOUS_APP`) and **23 named scam types** (`trustguard/scam/types.py`).
Examples:

- crypto casino / betting bonus, crypto giveaway, wallet drainer
- UPI payment fraud, OTP theft, fake customer support
- digital arrest, fake e-challan
- malicious app

**Link signals:**

- a `crypto_gambling_domain` signal
- `.win`, `.bet` and `.pw` added to the frequently abused TLDs
- lookalike signals now carry the imitated organisation, used to name the scam type
- crypto exchanges and wallets (Binance, Coinbase, MetaMask, Trust Wallet, WazirX, CoinDCX, CoinSwitch) and Microsoft
  added to the impersonation registry

### The exact casino message now

**HIGH 70 under balanced sensitivity** (threshold 50), HIGH 67 conservative, CRITICAL 70 aggressive.

- **Type:** "Crypto casino / betting bonus scam".
- **Confidence:** Medium (0.63), shown separately from the score.
- **All 11 requested signals are named as findings:**
  - large reward
  - everyone
  - registration
  - instant withdrawal
  - crypto context
  - casino context
  - outside site
  - promo code
  - urgency / scarcity
  - post will disappear
  - unverified partnership

The verdict says the link (nyxwin.com) could not be verified, and that the verdict rests on what the message says and
asks for, **not** on proof that the site is malicious.

Variants are all HIGH 59–63:

- other amounts (₹50,000, 2 ETH, 500 USDT)
- other sites and codes
- Hinglish
- `n y x w i n dot com` / leetspeak

The post is a permanent regression case: `D001`, and `tests/test_detection.py`.

### False positives

- **Single ingredients are context, not signals.** A mention of crypto, a casino, a promo code or a link scores 0 and is
  listed separately as "Context noted - not counted in the score".
- **Disclosures raise the bar.** Promotions with T&C, 18+ or market-risk text need three mechanics instead of two, and
  get a −4 mitigation.
- **Official-app instructions get a −4 mitigation.** A message that points to the official app, with no link, number or
  payment request, is treated as more likely genuine.
- **Narrower rules:**
  - Lottery *results* are separated from lottery *claims*.
  - A salary or festival bonus is not an "unrealistic reward".
  - The standard OTP advisory no longer triggers "secrecy".
- **Warnings and quotes:**
  - Quoted or reported wording ("messages promising…") and links that are only quoted are not held against a warning.
  - News and police warnings ("police warn of fake…", "researchers warned about…") are recognised.
  - Scam openers such as "SBI Alert:" deliberately are not.
- **Negative cases in the development set:** genuine crypto announcements, investment education, lawful casino adverts,
  disclosed promotions, cashback, bank and government messages, real e-challans, news, awareness posts and fact-checks.

---

## B. Accuracy evaluation

**Protocol.**

- A held-out set of 133 rows was frozen **before** any rule change (commit `83c034e`; its SHA-256 is pinned by a test)
  and never tuned against.
- Rules were tuned only on the development set, which now has 162 rows.
- Details and per-category tables: [evaluation.md](evaluation.md).

**Held-out set, before → after:**

| Measure | Before | After |
|---|---|---|
| Likely-scam (HIGH+) recall | 0.519 (42/81) | **0.815** (66/81) |
| Likely-scam precision | 1.000 | 1.000 |
| Likely-scam F1 | 0.683 | **0.898** |
| Alert (MEDIUM+) recall | 0.692 | **0.923** |
| Alert precision | 0.969 | **1.000** |
| Alert F1 | 0.808 | **0.960** |
| False-positive rate, alert (genuine and neutral rated MEDIUM+) | 0.048 | **0.000** |
| False-positive rate, likely scam | 0.000 | 0.000 |
| Genuine not rated LOW (strict) | 3/40 | 1/40 (INCONCLUSIVE) |
| Crypto casino / giveaway / wallet rated HIGH+ | 3/19 | **17/19** |

**Confusion matrix of the threat rows** (LOW / INCONCLUSIVE / MEDIUM / HIGH / CRITICAL):

- before: 16 / 10 / 13 / 24 / 18
- after: 4 / 1 / 10 / 45 / 21

**Development set:**

- 70/70 threats HIGH+
- 17/17 hoaxes flagged
- 0 genuine messages MEDIUM+ (one INCONCLUSIVE)

This is a regression gate, not a benchmark.

**Limitations.**

- Both sets are synthetic and written by the project. Expect lower real-world recall.
- Categories are small: 2–10 rows each.
- The runs are offline.
- The risk score is not a calibrated probability.
- No statistical-significance claim is made. The 95% Wilson intervals for HIGH+ recall on this set (0.41–0.62 before,
  0.72–0.88 after) describe only this set.

**Remaining weaknesses:** 15 held-out threats below HIGH. They are reported, not tuned away:

- OTP-theft messages without a link or number (LOW)
- one UPI story and one job offer without the usual lure words (LOW)
- lottery and advance-fee messages at MEDIUM 25–47
- fake-APK links at MEDIUM 41
- three bank, KYC or e-challan messages at MEDIUM 41–49
- one casino post whose only signal is an unverifiable link (INCONCLUSIVE)

---

## C. Moderator activity log

**What is recorded.** Only `login`, `scan` and `feedback`.

- `AccountStore._record()` refuses any other event type.
- Each row holds account id, username, role and time.
- A scan row adds its type, verdict and scan id.
- A feedback row adds its category and reference (`FB-000123`).

**Stopped at the source:**

- `auth.log_page` was removed, along with the page-view call in `streamlit_app.py`.
- Sign-up, sign-out, failed sign-in, wrong PIN, lockout, suspension, unlock, password change, feedback reply and session
  expiry no longer write activity rows.
- Traffic analytics and the moderator charts now show sign-ins, scans, feedback and active accounts. Page views and
  failed sign-ins are gone.

**No duplicates.**

- A partial unique index on `(event, ref)` with `INSERT … ON CONFLICT DO NOTHING`, keyed by scan id and feedback
  reference.
- A Streamlit rerun, a repeated callback or an API retry (`Idempotency-Key`) cannot add a second row.
- A successful sign-in writes exactly one row.

**Security kept.**

- Failed-attempt counters and lockouts live on the account row.
- Sign-up PIN failures go to a new `security_events` table, which the "pause moderator sign-up" throttle reads.
- Five wrong passwords still lock an account for 15 minutes. This was verified on a migrated old database.

**Migration.**

- Schema v2 keeps old rows but hides retired event types.
- The SQLite file is backed up first.
- `python -m trustguard.dbtools prune-activity` deletes them for good, after another backup.
- Verified on a database created by the old code:
  - 10 old rows, 3 visible
  - lockout still works
  - old scans readable
  - prune removed 7 rows after a backup

**Tests** (`tests/test_accounts.py`, `tests/test_app.py`), including:

- one login → one entry; a failed login → none
- page visits and navigation → none; reruns → no duplicate
- one scan → one entry; one feedback → one entry
- moderator actions → none
- no raw contents in the feed
- lockout still works
- legacy-database migration with backup

---

## D. UI redesign

**Palette:**

| Role | Colour |
|---|---|
| Background | `#0B1220` |
| Surfaces | `#111C2E`, `#17243A` |
| Borders | `#29384F` |
| Text | `#E6EDF7`, `#94A3B8` |
| Teal accent | `#20C9B5` |
| Cyan accent | `#38BDF8` |
| Risk: LOW | `#22C55E` |
| Risk: MEDIUM | `#FBBF24` |
| Risk: HIGH | `#FB923C` |
| Risk: CRITICAL | `#F43F5E` |
| Risk: INCONCLUSIVE | `#94A3B8` |

**One token system** (`app/theme.py`).

- The CSS is built from CSS variables. Charts and the sidebar status use the tokens.
- `.streamlit/config.toml` is **generated** by `scripts/sync_theme.py`.
- A test fails if the two disagree, or if any page contains a colour literal.

**Components changed:**

- **Verdict card.**
  - The level shows a word **and** an icon.
  - Score and confidence sit in separate boxes. Confidence is explained as "not a probability".
  - A segmented scale with a marker, a scam-type chip and a one-line explanation of the scam type.
  - Facts: evidence counts and link-check status.
- **Findings.**
  - Severity with an icon, a "Confirmed indicator / Strong pattern / Weak signal" badge, and the triggering fragment.
  - "Found in", "Detected by", category and confidence.
  - Context notes in their own list.
- **Link report:** a check-status pill (checked / partly checked / not checked live / not visited / unreachable) and a
  note.
- **New App analysis tab:**
  - the app's facts
  - signing, with test-key and debug-certificate badges
  - permissions in plain language
  - exported components
  - capabilities seen in the code
  - defanged links
  - limitations
- **Buttons:** teal with dark text, because white on teal fails contrast.
- **Forms, tables and empty states:**
  - visible focus rings
  - form outlines at 3:1 contrast
  - restyled HTML tables
  - empty states with an icon
- **Other pages:**
  - Scan history: a scam-type column and level icons.
  - Moderator overview: a service-health panel.
  - New teal logo.

**Accessibility.** Tests check WCAG AA for every text and background pair the UI uses, and 3:1 for form-control outlines
and risk colours. The design honours `prefers-reduced-motion`. Risk is never shown by colour alone.

**Responsive.** The sidebar starts collapsed on phones, the verdict card stacks, and long tokens wrap. It was checked at
390 px.

**Screenshots** in `docs/screenshots/` were regenerated from the running app.

---

## E. Performance and scalability

**Architecture changes:**

- **Bounded scan slots** per process: 8 scans, 2 file scans. If no slot frees up within 20 s, the API answers 503 with
  `Retry-After`; requests never queue without limit.
- The file route is synchronous, so PDF, OCR and APK parsing run in the thread pool, not on the event loop.
- **Upload limits:** 15 MB, or 50 MB for APKs, checked before parsing. 413 when exceeded.
- **Idempotency keys** on every scan.
- **Database layer** (`trustguard/db.py`):
  - SQLite with WAL, `busy_timeout`, per-thread connections and short transactions
  - PostgreSQL through `psycopg` 3 with a pool
  - versioned migrations with automatic backups
  - `dbtools`: check, backup, prune-activity, copy-to-postgres (verified on old data)
- **Rate limits** (`trustguard/ratelimit.py`): sliding window, bounded in memory, shared through Redis with fallback,
  hashed keys, trusted-proxy handling, 429 with `Retry-After`. There are scan, file, API-wide and per-account web-app
  limits.
- **Threat-intelligence resilience:**
  - shared connection pools
  - at most 4 calls per provider at once
  - circuit breakers (3 failures → 60 s pause → one trial call)
  - one retry for connection errors and 502/503/504
  - parallel lookups with a deadline
  - "unavailable" or "no answer in time", never "not listed"
  - error text scrubbed of URLs and keys
- **Metrics:** `/metrics` (Prometheus) and `/v1/ops/stats`. They hold counts, p50, p95 and p99, error rate, rejections,
  database errors, provider states, CPU and memory, and no content.
- **Docker:** `docker-compose.yml` now shares one volume between the UI and the API. Before, the UI lost its accounts on
  every rebuild and couldn't read the API token. New `docker-compose.prod.yml` with PostgreSQL, Redis and 4 API workers.

**Measured** on a 2-vCPU VM with 2 API workers, offline, and Locust on the same machine. Full results are in
[load-testing.md](load-testing.md).

| Scenario | 100 users, req/s | p50 | p95 | p99 | errors |
|---|---|---|---|---|---|
| message (SQLite) | 97.9 | 14 ms | 42 ms | 66 ms | 0 |
| link, offline (SQLite) | 99.5 | 9 ms | 24 ms | 42 ms | 0 |
| file (SQLite) | 74.6 | 320 ms | 640 ms | 860 ms | 0 |
| message (PostgreSQL) | 97.9 | 22 ms | 73 ms | 110 ms | 0 |
| file (PostgreSQL) | 61.0 | 650 ms | 980 ms | 1.4 s | 0 |
| message, no pause (saturation) | 191.5 | 470 ms | 980 ms | 1.6 s | 0 |

- 10, 25 and 50 users were also run for every scenario, all with 0 errors.
- **Deliberate burst** (20 users, no pause, one address): 28k requests, answered with 429s, 0 errors, and the server
  stayed healthy.
  - With in-memory limits 64 requests got through, because each of the two workers counts separately.
  - With Redis exactly 30 got through, the configured limit.

**Tested limits.**

- Only this hardware was measured.
- Live link checks and threat intelligence were off during the load test. Their failure handling is covered by unit tests
  with fake providers.
- OCR, APK uploads and the Streamlit UI were not load-tested.

---

## F. Security

**Fixed:**

- **The API ownership boundary.**
  - Before, `X-Verioax-Owner` was trusted from any caller, and the token was optional. Anyone who could reach the API
    could read, list or delete any account's scans and change preferences.
  - Now the API always requires a bearer token. If none is configured, it generates one into `api.token` (0600).
  - The only exemption is a **direct** request from the same machine with no proxy headers, and only while no token is
    configured.
  - The owner header is honoured only on authenticated requests.
- **Errors and keys.**
  - Validation errors no longer echo the submitted text.
  - Provider error text can't carry URLs or API keys.
  - Redis keys hold hashes, not IP addresses.
  - Metrics hold no content.
- **Activity records** contain no message text, links, file names or personal data.
- **Uploads.**
  - The type is detected from the content.
  - ZIP-bomb guards cover DOCX.
  - Plain ZIP files are refused.
  - The size limit is enforced before parsing.
  - PDF page and time limits; image decompression limits.
- **APK handling:**
  - read in memory, never written to disk, installed, executed or uploaded
  - limits on entries, compression ratio, declared size, per-part size and time
  - path traversal and duplicate entries reported
  - INCONCLUSIVE (never "safe") when it can't be parsed
  - a test asserts that no subprocess or network call happens during an APK scan
- **Concurrent start-up.** Several workers starting together no longer race to create different tokens or keys
  (`O_EXCL`).

**Retained and still tested:** the SSRF-guarded fetcher, with:

- public-IP only, and private, loopback, link-local and metadata ranges blocked
- connections pinned to the validated address (no DNS rebinding)
- every redirect re-validated
- ports 80 and 443 only
- a 1.5 MB cap and timeouts

Also retained:

- scrypt passwords, lockouts and the moderator PIN kept in the environment
- redaction before any outside call
- defanged, non-clickable links
- `SecretStr` keys

**Remaining concerns:**

- One shared moderator PIN.
- The same-machine exemption trusts every local process. Set `TRUSTGUARD_API_TOKEN` on shared servers.
- Per-IP limits can be spread over many addresses.
- APK signatures are read, not cryptographically verified.
- Sign-in lasts one browser tab, by design.

---

## G. Files changed

**New:**

- engine: `trustguard/scam/normalize.py`, `trustguard/scam/money.py`, `trustguard/scam/types.py`,
  `trustguard/appscan.py`, `trustguard/extract/apk.py`
- infrastructure: `trustguard/db.py`, `trustguard/dbtools.py`, `trustguard/ratelimit.py`, `trustguard/metrics.py`,
  `trustguard/intel/resilience.py`
- UI: `app/theme.py`, `scripts/sync_theme.py`
- data and deployment: `data/eval/holdout.jsonl`, `docker-compose.prod.yml`
- docs: `docs/evaluation.md`, `docs/deployment.md`, `docs/load-testing.md`, this report
- tests: `tests/test_detection.py`, `tests/test_api.py`, `tests/test_apk.py`, `tests/apkfactory.py`, `tests/test_db.py`,
  `tests/test_ratelimit.py`, `tests/test_resilience.py`, `tests/test_theme.py`, `tests/load/locustfile.py`,
  `tests/load/run_load.py`
- three new screenshots

**Modified:**

- engine: `trustguard/scam/indicators.py`, `trustguard/scam/analyzer.py`, `trustguard/scam/claims.py`,
  `trustguard/risk.py`, `trustguard/findings.py`, `trustguard/schemas.py`, `trustguard/engine.py`,
  `trustguard/recommend.py`, `trustguard/brands.py`, `trustguard/url/lexical.py`, `trustguard/url/parse.py`,
  `trustguard/url/analyzer.py`, `trustguard/intel/__init__.py`, `trustguard/intel/providers.py`,
  `trustguard/extract/__init__.py`, `trustguard/reports/__init__.py`, `trustguard/evaluation.py`
- storage and config: `trustguard/accounts.py`, `trustguard/storage.py`, `trustguard/config.py`
- API: `api/main.py`
- UI: `app/ui.py`, `app/results.py`, `app/client.py`, `app/state.py`, `app/auth.py`, `app/charts.py`,
  `app/streamlit_app.py`, `app/views/` (scan_file, history, mod_overview, mod_activity, mod_accounts, feedback, signin),
  `app/static/logo*.svg`
- data and tests: `data/eval/messages.jsonl`, `tests/test_accounts.py`, `tests/test_app.py`, `tests/test_eval.py`,
  `tests/test_reports_api.py`
- config and docs: `.streamlit/config.toml`, `docker-compose.yml`, `.github/workflows/ci.yml`, `.env.example`,
  `.gitignore`, `pyproject.toml`, `requirements.txt`, `README.md`, `docs/architecture.md`, `docs/scoring.md`
- screenshots

---

## H. How to run

```bash
pip install -r requirements.txt               # Windows PowerShell: the same command inside your .venv
copy .env.example .env                        # Linux/macOS: cp .env.example .env ; then set VERIOAX_MODERATOR_PIN
streamlit run app/streamlit_app.py            # web app  http://localhost:8501
uvicorn api.main:app --port 8000 --workers 2  # REST API http://localhost:8000/docs
docker compose up --build                     # both, one machine
docker compose -f docker-compose.prod.yml up --build -d   # PostgreSQL + Redis + 4 API workers
pytest -q ; ruff check . ; python -m trustguard.evaluation --set all
python tests/load/run_load.py                 # needs: pip install locust psutil
python -m trustguard.dbtools check | backup | prune-activity | copy-to-postgres --to <url>
```

**New environment variables** (all optional): `VERIOAX_DATABASE_URL`, `VERIOAX_DATABASE_POOL_SIZE`, `VERIOAX_REDIS_URL`,
`VERIOAX_SECRET_KEY`, `VERIOAX_RATE_LIMIT_SCAN` / `_FILE` / `_API` / `_UI_SCAN`, `VERIOAX_TRUSTED_PROXIES`,
`VERIOAX_MAX_CONCURRENT_SCANS`, `VERIOAX_MAX_CONCURRENT_FILE_SCANS`, `VERIOAX_SCAN_QUEUE_TIMEOUT_S`. For tests only:
`VERIOAX_TEST_POSTGRES_URL` and `VERIOAX_TEST_REDIS_URL`.

`TRUSTGUARD_API_TOKEN` keeps its name. When it is empty, a token is generated into `api.token`.

No new mandatory API key: everything still works offline.

---

## I. Remaining work

- **Detection gaps** on the held-out set (section B). They need new development examples and rules: OTP theft without
  links, lottery and advance-fee messages below HIGH, fake-APK links.
- **Real-world data.** A real, consented message corpus would turn the synthetic evaluation into a real one, and allow
  calibrating the score.
- **APK.** No dynamic analysis, no cryptographic signature verification, no known-malware hash lookup. A hash lookup
  would need an explicit, separate opt-in.
- **Not exercised here:**
  - Docker (no Docker daemon in this environment). Both compose files were validated with `docker compose config`, and
    the same uvicorn and Streamlit commands were run directly.
  - Windows native runs (the patch was test-applied with Windows line endings).
  - Load tests with live providers, OCR or APKs, and of the Streamlit UI.
- **Product.** PDF reports still lack a Devanagari font. The UI is English-only. Moderators share one PIN.
