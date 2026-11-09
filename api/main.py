"""Verioax REST API (FastAPI).

Run:  uvicorn api.main:app --port 8000      docs: http://localhost:8000/docs

Security notes (the API accepts attacker-controlled input by design):
* optional bearer token (TRUSTGUARD_API_TOKEN) on every /v1 route;
* per-client rate limit on scan endpoints (live link checks are expensive and must not become an open proxy);
* request size limits (message 20,000 characters, file 15 MB) enforced before any processing;
* responses never contain raw PII: only the audit-safe ScanResult (placeholders, hashes, redacted text, defanged links);
* request bodies are never logged; errors return a generic message, not internals.
"""
from __future__ import annotations

import hmac
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from trustguard import __version__, analytics, reports
from trustguard.config import Preferences, get_settings, save_preferences
from trustguard.engine import MAX_MESSAGE_CHARS, InputError, TrustGuardEngine
from trustguard.schemas import AnalysisMode, ScanResult

log = logging.getLogger("trustguard.api")
MAX_FILE_BYTES = 15 * 1024 * 1024
SCANS_PER_MINUTE = 30


class MessageScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS, description="SMS, WhatsApp message, email body ...")
    sender: str | None = Field(default=None, max_length=120, description="Sender header (VM-HDFCBK-S), phone number or email address")
    mode: AnalysisMode = AnalysisMode.FULL
    demo: bool = Field(default=False, description="Mark the stored scan as sample data (used by the dashboard's demo loader)")


class URLScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                raise HTTPException(429, "Too many scans - please wait a minute.")
            q.append(now)


def create_app(engine: TrustGuardEngine | None = None) -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Verioax", version=__version__,
                  description="PII redaction + explainable scam, hoax and link-integrity analysis.")
    app.state.engine = engine
    limiter = RateLimiter(SCANS_PER_MINUTE)
    token = settings.api_token.get_secret_value() if settings.api_token else None

    def get_engine() -> TrustGuardEngine:
        if app.state.engine is None:
            app.state.engine = TrustGuardEngine()
        return app.state.engine

    def auth(request: Request) -> None:
        if token is None:
            return
        header = request.headers.get("authorization", "")
        if not (header.startswith("Bearer ") and hmac.compare_digest(header[7:], token)):
            raise HTTPException(401, "Missing or invalid API token.", headers={"WWW-Authenticate": "Bearer"})

    def rate(request: Request) -> None:
        limiter.check(request.client.host if request.client else "unknown")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.exception_handler(InputError)
    async def input_error(_: Request, exc: InputError):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception):           # never echo internals (or input) back
        log.error("unhandled error: %s", type(exc).__name__)
        return JSONResponse({"detail": "Internal error while analysing the input."}, status_code=500)

    # ------------------------------------------------------------------ health
    @app.get("/health")
    def health(eng: TrustGuardEngine = Depends(get_engine)):
        return {"status": "ok", "version": __version__, "network_mode": "local" if eng.prefs.local_mode else "online",
                "providers": [{"provider": r["provider"], "state": r["state"]} for r in eng.hub.status()]}

    # ------------------------------------------------------------------ scans
    @app.post("/v1/scan/message", response_model=ScanResult, dependencies=[Depends(auth), Depends(rate)])
    def scan_message(req: MessageScanRequest, eng: TrustGuardEngine = Depends(get_engine)):
        return eng.scan_message(req.text, sender=req.sender, mode=req.mode, demo=req.demo).result

    @app.post("/v1/scan/url", response_model=ScanResult, dependencies=[Depends(auth), Depends(rate)])
    def scan_url(req: URLScanRequest, eng: TrustGuardEngine = Depends(get_engine)):
        return eng.scan_url(req.url).result

    @app.post("/v1/scan/file", response_model=ScanResult, dependencies=[Depends(auth), Depends(rate)])
    async def scan_file(file: UploadFile = File(...), mode: AnalysisMode = Form(AnalysisMode.FULL), eng: TrustGuardEngine = Depends(get_engine)):
        data = await file.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise HTTPException(413, f"File too large (limit {MAX_FILE_BYTES // (1024 * 1024)} MB).")
        return eng.scan_file(file.filename or "upload", data, mode=mode).result

    # ------------------------------------------------------------------ history
    @app.get("/v1/scans", dependencies=[Depends(auth)])
    def list_scans(risk: list[str] | None = Query(None), input_type: list[str] | None = Query(None), category: str | None = None,
                   search: str | None = Query(None, max_length=80), since: datetime | None = None, until: datetime | None = None,
                   limit: int = Query(100, le=1000),
                   eng: TrustGuardEngine = Depends(get_engine)):
        if eng.store is None:
            return []
        return eng.store.list(limit=limit, risk=risk, input_type=input_type, category=category, search=search, since=since, until=until)

    def _get(scan_id: str, eng: TrustGuardEngine) -> ScanResult:
        r = eng.store.get(scan_id) if eng.store else None
        if r is None:
            raise HTTPException(404, "Scan not found.")
        return r

    @app.get("/v1/scans/{scan_id}", response_model=ScanResult, dependencies=[Depends(auth)])
    def get_scan(scan_id: str, eng: TrustGuardEngine = Depends(get_engine)):
        return _get(scan_id, eng)

    @app.delete("/v1/scans/{scan_id}", dependencies=[Depends(auth)])
    def delete_scan(scan_id: str, eng: TrustGuardEngine = Depends(get_engine)):
        if not (eng.store and eng.store.delete(scan_id)):
            raise HTTPException(404, "Scan not found.")
        return {"deleted": scan_id}

    @app.get("/v1/scans/{scan_id}/report.{fmt}", dependencies=[Depends(auth)])
    def scan_report(scan_id: str, fmt: Literal["json", "csv", "md", "pdf"], eng: TrustGuardEngine = Depends(get_engine)):
        r = _get(scan_id, eng)
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

    @app.post("/v1/intel/test/{provider}", dependencies=[Depends(auth), Depends(rate)])
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
