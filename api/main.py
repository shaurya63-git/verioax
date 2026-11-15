"""Verioax REST API (FastAPI).

Run:  uvicorn api.main:app --port 8000      docs: http://localhost:8000/docs
Production (several workers, shared PostgreSQL + Redis): see docs/deployment.md.

Security model (the API accepts attacker-controlled input by design):

* **Authentication.** Every /v1 route and /metrics need ``Authorization: Bearer <token>``. The token is
  TRUSTGUARD_API_TOKEN or, when that is unset, a random token the API writes to ``data_dir/api.token`` at start-up.
  The only exception is local development: a direct request from this machine (loopback address, no proxy headers)
  is accepted without a token *only while no token is configured in the environment*. Anything that arrives through a
  proxy or from another machine always needs the token.
* **Accounts.** The token is a service credential for the Verioax web app, which signs users in itself and tells the
  API which account a request is for in ``X-Verioax-Owner``. That header is honoured only on authenticated requests;
  an unauthenticated caller can never pick an owner, so it can't read or delete another account's scans. Don't hand
  the token to end users.
* **Limits.** Per-client request limits (shared across workers through Redis when VERIOAX_REDIS_URL is set), a
  bounded number of scans in progress (HTTP 503 + Retry-After when full), message 20,000 characters, files 15 MB
  (APKs 50 MB), all enforced before any processing.
* **Privacy.** Responses contain only the audit-safe ScanResult (placeholders, hashes, redacted text, defanged links).
  Request bodies are never logged; errors return a generic message; metrics carry no content, links or account names.
"""
from __future__ import annotations

import hmac
import logging
import re
import time
from datetime import datetime
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from trustguard import __version__, analytics, db, reports
from trustguard.config import Preferences, get_settings, resolve_api_token, save_preferences
from trustguard.engine import MAX_MESSAGE_CHARS, BusyError, InputError, TooLargeError, TrustGuardEngine
from trustguard.extract import MAX_APK_BYTES
from trustguard.metrics import REGISTRY
from trustguard.ratelimit import Rate, client_ip, is_loopback, make_limiter, parse_networks
from trustguard.schemas import AnalysisMode, ScanResult

log = logging.getLogger("trustguard.api")
_IDEM = re.compile(r"^[A-Za-z0-9_.:-]{8,100}$")
_PROXY_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip")


class MessageScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS, description="SMS, WhatsApp message, email body ...")
    sender: str | None = Field(default=None, max_length=120, description="Sender header (VM-HDFCBK-S), phone number or email address")
    mode: AnalysisMode = AnalysisMode.FULL
    demo: bool = Field(default=False, description="Mark the stored scan as sample data (used by the dashboard's demo loader)")


class URLScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


def create_app(engine: TrustGuardEngine | None = None) -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Verioax", version=__version__,
                  description="PII redaction + explainable scam, hoax, link-integrity and Android-app analysis.")
    app.state.engine = engine
    env_token = settings.api_token.get_secret_value() if settings.api_token else None
    token = resolve_api_token(settings, create=True)
    trusted = parse_networks(settings.trusted_proxies)
    limiter = make_limiter(settings.redis_url.get_secret_value() if settings.redis_url else None,
                           on_error=lambda name: REGISTRY.inc("ratelimit_backend_errors", error=name))
    rates = {"api": Rate.parse(settings.rate_limit_api), "scan": Rate.parse(settings.rate_limit_scan), "file": Rate.parse(settings.rate_limit_file)}
    db.on_error = lambda name: REGISTRY.inc("db_errors_total", error=name)

    def get_engine() -> TrustGuardEngine:
        if app.state.engine is None:
            app.state.engine = TrustGuardEngine()
        return app.state.engine

    def _client(request: Request) -> str:
        return client_ip(request.client.host if request.client else None, request.headers.get("x-forwarded-for"), trusted)

    def _authenticated(request: Request) -> bool:
        header = request.headers.get("authorization", "")
        if header.startswith("Bearer ") and token and hmac.compare_digest(header[7:].encode(), token.encode()):
            return True
        # local development: a direct request from this machine, while no token is configured in the environment
        direct = not any(h in request.headers for h in _PROXY_HEADERS)
        return env_token is None and direct and request.client is not None and is_loopback(request.client.host)

    def auth(request: Request) -> None:
        if not _authenticated(request):
            raise HTTPException(401, "Missing or invalid API token.", headers={"WWW-Authenticate": "Bearer"})

    def _limit(request: Request, scope: str, key: str | None = None) -> None:
        d = limiter.hit(f"{scope}:{key or _client(request)}", rates[scope])
        if not d.allowed:
            REGISTRY.inc("rate_limited_total", scope=scope)
            raise HTTPException(429, f"Too many requests - please wait {d.retry_after} second(s).", headers={"Retry-After": str(d.retry_after)})

    def scan_rate(request: Request) -> None:
        _limit(request, "scan")

    def file_rate(request: Request) -> None:
        _limit(request, "file")

    def owner(request: Request, x_verioax_owner: int | None = Header(None, ge=1, description=(
            "Account id of the web-app user the request is made for. Only honoured on requests authenticated with the API token "
            "(the Verioax web app's service credential); scans are stored under that account and history is filtered to it."))) -> int | None:
        if x_verioax_owner is not None and not _authenticated(request):
            raise HTTPException(401, "X-Verioax-Owner needs an authenticated request.")
        return x_verioax_owner

    def idem(idempotency_key: str | None = Header(None, description="Optional: retries with the same key return the first result.")) -> str | None:
        if idempotency_key is not None and not _IDEM.fullmatch(idempotency_key):
            raise HTTPException(422, "Idempotency-Key must be 8-100 characters: letters, digits, '_', '-', '.', ':'.")
        return idempotency_key

    # ------------------------------------------------------------------ middleware: limits, metrics, headers
    @app.middleware("http")
    async def frame(request: Request, call_next):
        t = time.perf_counter()
        status, route = 500, "other"
        try:
            if request.url.path.startswith("/v1/"):
                d = limiter.hit(f"api:{_client(request)}", rates["api"])
                if not d.allowed:
                    REGISTRY.inc("rate_limited_total", scope="api")
                    status = 429
                    return _secure(JSONResponse({"detail": f"Too many requests - please wait {d.retry_after} second(s)."}, status_code=429,
                                                headers={"Retry-After": str(d.retry_after)}))
            resp = await call_next(request)
            status = resp.status_code
            route = getattr(request.scope.get("route"), "path", "other")      # the route template, never the concrete URL
            return _secure(resp)
        finally:
            outcome = "ok" if status < 400 else "rejected" if status in (401, 403, 404, 405, 413, 422, 429, 503) else "error"
            REGISTRY.inc("requests_total", route=route, status=status, outcome=outcome)
            REGISTRY.observe(f"http {route}", time.perf_counter() - t)

    def _secure(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, exc: RequestValidationError):
        # FastAPI's default handler echoes the submitted value back ("input"); that value can be a message, a link or
        # personal data, so only the location and the reason are returned
        errors = [{"loc": [str(x) for x in e.get("loc", ())], "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    @app.exception_handler(InputError)
    async def input_error(_: Request, exc: InputError):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(TooLargeError)
    async def too_large(_: Request, exc: TooLargeError):
        return JSONResponse({"detail": str(exc)}, status_code=413)

    @app.exception_handler(BusyError)
    async def busy(_: Request, exc: BusyError):
        return JSONResponse({"detail": str(exc)}, status_code=503, headers={"Retry-After": str(exc.retry_after)})

    @app.exception_handler(db.DatabaseError)
    async def database_down(_: Request, exc: db.DatabaseError):
        log.error("database error: %s", type(exc).__name__)
        return JSONResponse({"detail": "The database is not available right now. Please try again shortly."}, status_code=503,
                            headers={"Retry-After": "10"})

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception):           # never echo internals (or input) back
        log.error("unhandled error: %s", type(exc).__name__)
        return JSONResponse({"detail": "Internal error while analysing the input."}, status_code=500)

    # ------------------------------------------------------------------ health and operations
    @app.get("/health")
    def health():
        """Liveness: the process answers. No data, no secrets."""
        return {"status": "ok", "version": __version__}

    @app.get("/ready")
    def ready(eng: TrustGuardEngine = Depends(get_engine)):
        """Readiness: the scan history database answers."""
        ms = eng.store.db.ping() if eng.store else None
        return {"status": "ok", "database": eng.store.db.dialect if eng.store else "none", "db_ping_ms": ms,
                "network_mode": "local" if eng.prefs.local_mode else "online", "rate_limiter": limiter.backend}

    @app.get("/metrics", dependencies=[Depends(auth)], response_class=PlainTextResponse)
    def metrics():
        return PlainTextResponse(REGISTRY.prometheus(), media_type="text/plain; version=0.0.4")

    @app.get("/v1/ops/stats", dependencies=[Depends(auth)])
    def ops_stats(eng: TrustGuardEngine = Depends(get_engine)):
        snap = REGISTRY.snapshot()
        snap["limits"] = {k: f"{v.limit}/{v.window_s}s" for k, v in rates.items()} | {"rate_limiter": limiter.backend,
                                                                                       "max_concurrent_scans": settings.max_concurrent_scans,
                                                                                       "max_concurrent_file_scans": settings.max_concurrent_file_scans}
        snap["providers"] = eng.hub.health()
        return snap

    # ------------------------------------------------------------------ scans
    @app.post("/v1/scan/message", response_model=ScanResult, dependencies=[Depends(auth), Depends(scan_rate)])
    def scan_message(req: MessageScanRequest, eng: TrustGuardEngine = Depends(get_engine), owner_id: int | None = Depends(owner),
                     key: str | None = Depends(idem)):
        return eng.scan_message(req.text, sender=req.sender, mode=req.mode, demo=req.demo, owner_id=owner_id, idempotency_key=key).result

    @app.post("/v1/scan/url", response_model=ScanResult, dependencies=[Depends(auth), Depends(scan_rate)])
    def scan_url(req: URLScanRequest, eng: TrustGuardEngine = Depends(get_engine), owner_id: int | None = Depends(owner),
                 key: str | None = Depends(idem)):
        return eng.scan_url(req.url, owner_id=owner_id, idempotency_key=key).result

    @app.post("/v1/scan/file", response_model=ScanResult, dependencies=[Depends(auth), Depends(file_rate)])
    def scan_file(file: UploadFile = File(...), mode: AnalysisMode = Form(AnalysisMode.FULL), eng: TrustGuardEngine = Depends(get_engine),
                  owner_id: int | None = Depends(owner), key: str | None = Depends(idem)):
        # a plain (sync) endpoint: FastAPI runs it in its worker threads, so parsing a PDF or an APK never blocks the event loop.
        # The upload is already spooled to a temporary file; the engine reads it only once it has a file-scan slot.
        if file.size is not None and file.size > MAX_APK_BYTES:
            raise HTTPException(413, f"File too large (limit {MAX_APK_BYTES // (1024 * 1024)} MB).")
        return eng.scan_file(file.filename or "upload", file.file, mode=mode, owner_id=owner_id, idempotency_key=key).result

    # ------------------------------------------------------------------ history
    @app.get("/v1/scans", dependencies=[Depends(auth)])
    def list_scans(risk: list[str] | None = Query(None), input_type: list[str] | None = Query(None), category: str | None = None,
                   search: str | None = Query(None, max_length=80), since: datetime | None = None, until: datetime | None = None,
                   limit: int = Query(100, le=1000),
                   eng: TrustGuardEngine = Depends(get_engine), owner_id: int | None = Depends(owner)):
        if eng.store is None:
            return []
        return eng.store.list(limit=limit, risk=risk, input_type=input_type, category=category, search=search, since=since, until=until,
                              owner_id=owner_id)

    def _get(scan_id: str, eng: TrustGuardEngine, owner_id: int | None = None) -> ScanResult:
        r = eng.store.get(scan_id, owner_id=owner_id) if eng.store else None
        if r is None:
            raise HTTPException(404, "Scan not found.")
        return r

    @app.get("/v1/scans/{scan_id}", response_model=ScanResult, dependencies=[Depends(auth)])
    def get_scan(scan_id: str, eng: TrustGuardEngine = Depends(get_engine), owner_id: int | None = Depends(owner)):
        return _get(scan_id, eng, owner_id)

    @app.delete("/v1/scans/{scan_id}", dependencies=[Depends(auth)])
    def delete_scan(scan_id: str, eng: TrustGuardEngine = Depends(get_engine), owner_id: int | None = Depends(owner)):
        if not (eng.store and eng.store.delete(scan_id, owner_id=owner_id)):
            raise HTTPException(404, "Scan not found.")
        return {"deleted": scan_id}

    @app.get("/v1/scans/{scan_id}/report.{fmt}", dependencies=[Depends(auth)])
    def scan_report(scan_id: str, fmt: Literal["json", "csv", "md", "pdf"], eng: TrustGuardEngine = Depends(get_engine),
                    owner_id: int | None = Depends(owner)):
        r = _get(scan_id, eng, owner_id)
        name = f"verioax-{scan_id}.{fmt}"
        disp = {"Content-Disposition": f'attachment; filename="{name}"'}
        if fmt == "pdf":
            return Response(reports.to_pdf(r), media_type="application/pdf", headers=disp)
        body, media = {"json": (reports.to_json(r), "application/json"), "csv": (reports.findings_csv(r), "text/csv"),
                       "md": (reports.to_markdown(r), "text/markdown")}[fmt]
        return PlainTextResponse(body, media_type=media, headers=disp)

    # ------------------------------------------------------------------ analytics
    @app.get("/v1/analytics", dependencies=[Depends(auth)])
    def get_analytics(eng: TrustGuardEngine = Depends(get_engine)):
        return analytics.summarize(eng.store.results(1000) if eng.store else [])

    @app.get("/v1/analytics/report.{fmt}", dependencies=[Depends(auth)])
    def analytics_report(fmt: Literal["json", "md", "pdf", "csv"], eng: TrustGuardEngine = Depends(get_engine)):
        summary = analytics.summarize(eng.store.results(1000) if eng.store else [])
        disp = {"Content-Disposition": f'attachment; filename="verioax-analytics.{fmt}"'}
        if fmt == "pdf":
            return Response(reports.analytics_pdf(summary), media_type="application/pdf", headers=disp)
        if fmt == "csv":
            return PlainTextResponse(reports.history_csv(eng.store.list(limit=1000) if eng.store else []), media_type="text/csv", headers=disp)
        body = reports.analytics_json(summary) if fmt == "json" else reports.analytics_markdown(summary)
        return PlainTextResponse(body, media_type="application/json" if fmt == "json" else "text/markdown", headers=disp)

    # ------------------------------------------------------------------ intel + preferences
    @app.get("/v1/intel/status", dependencies=[Depends(auth)])
    def intel_status(eng: TrustGuardEngine = Depends(get_engine)):
        return eng.hub.status()

    @app.post("/v1/intel/test/{provider}", dependencies=[Depends(auth), Depends(scan_rate)])
    def intel_test(provider: str, eng: TrustGuardEngine = Depends(get_engine)):
        try:
            return eng.hub.test(provider)
        except KeyError:
            raise HTTPException(404, "Unknown provider.") from None

    @app.get("/v1/preferences", response_model=Preferences, dependencies=[Depends(auth)])
    def get_prefs(eng: TrustGuardEngine = Depends(get_engine)):
        return eng.prefs

    @app.put("/v1/preferences", response_model=Preferences, dependencies=[Depends(auth)])
    def put_prefs(prefs: Preferences, eng: TrustGuardEngine = Depends(get_engine)):
        save_preferences(prefs, eng.settings)
        eng.update_preferences(prefs)
        return prefs

    return app


app = create_app()
