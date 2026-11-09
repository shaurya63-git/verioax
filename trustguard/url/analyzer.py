"""URL integrity analysis: static checks, then (when allowed) guarded live checks and threat intelligence.

Order of work for one link:
1. parse and run the static checks (``lexical``);
2. prepare a privacy-safe version: query parameters that carry personal data or unique IDs are removed; if personal
   data sits in the path, the link is not visited at all (visiting could confirm to the sender that you received it);
3. threat intelligence on the safe version (local IOC list always; online services only when enabled and configured);
4. live checks in the guarded fetcher: redirect chain (each hop validated), page inspection, TLS certificate and
   domain registration date (RDAP). The final destination of a redirect is analysed statically too.

Nothing here invents data: a check that could not run is reported as ``unavailable`` with the reason.
"""
from __future__ import annotations

import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..cache import TTLCache
from ..config import Preferences, Settings
from ..intel import IntelHub
from ..schemas import DomainInfo, PageInspection, RedirectHop, TLSInfo, URLCheck, URLReport
from ..schemas import ScamCategory as C
from ..schemas import Severity as SV
from ..schemas import Strength as ST
from . import lexical
from .content import PAYMENT_SECRETS, inspect_html
from .lexical import URLSignal
from .network import BlockedDestination, SafeFetcher, lookup_rdap, probe_tls, resolve_public
from .parse import ParsedURL, URLParseError, defang, parse

_PII_IN_PATH = re.compile(r"(?i)[^/@\s]+@[^/@\s]+\.[a-z]{2,}|(?<!\d)(?:\+?91)?[6-9]\d{9}(?!\d)|(?<![A-Z0-9])[A-Z]{2}\d{1,2}[A-Z]{0,3}\d{4}(?![A-Z0-9])")


@dataclass
class URLAnalysis:
    report: URLReport
    signals: list[tuple[URLSignal, str]] = field(default_factory=list)      # (signal, source: url | page | intel)
    claimed_mismatch_hosts: list[str] = field(default_factory=list)


def safe_version(p: ParsedURL, personal_params: list[str]) -> tuple[str, str | None]:
    """URL to use for lookups/visits, and a reason when the link must not be visited at all."""
    parts = urlsplit(p.url)
    if _PII_IN_PATH.search(parts.path or ""):
        return p.url, "the link's path contains what looks like personal data, so visiting it could confirm your identity to the sender"
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in personal_params]
    netloc = parts.netloc.rsplit("@", 1)[-1]                    # never send the userinfo part
    return urlunsplit((parts.scheme, netloc, parts.path or "/", urlencode(query), "")), None


def redact_url_for_display(url: str, personal_params: list[str]) -> str:
    if not personal_params:
        return url
    parts = urlsplit(url)
    query = [(k, "[REMOVED]" if k in personal_params else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, safe="[]"), parts.fragment))


class URLAnalyzer:
    def __init__(self, settings: Settings, prefs: Preferences, hub: IntelHub, cache: TTLCache | None = None,
                 fetcher: SafeFetcher | None = None, tls_probe: Callable[[str], TLSInfo] | None = None,
                 rdap: Callable[[str], DomainInfo] | None = None, resolver=socket.getaddrinfo):
        self.settings, self.prefs, self.hub, self.cache = settings, prefs, hub, cache
        self.fetcher = fetcher or SafeFetcher(timeout_s=settings.fetch_timeout_s, max_redirects=settings.max_redirects,
                                              max_bytes=settings.max_page_bytes, allowed_ports=settings.allowed_ports,
                                              user_agent=settings.user_agent, resolver=resolver)
        self._tls = tls_probe or (lambda host: probe_tls(host, timeout_s=settings.fetch_timeout_s, resolver=resolver))
        self._rdap = rdap or (lambda dom: lookup_rdap(dom, timeout_s=settings.fetch_timeout_s))
        self._resolver = resolver

    # ------------------------------------------------------------------ cached live helpers
    def _cached(self, key: str, ttl: float, fn, model):
        if self.cache is not None and (hit := self.cache.get(key)) is not None:
            return model.model_validate(hit)
        val = fn()
        if self.cache is not None and not getattr(val, "error", None):
            self.cache.set(key, val.model_dump(mode="json"), ttl)
        return val

    # ------------------------------------------------------------------ main
    def analyze(self, raw_url: str, *, url_id: str, claimed_entities: list[str] | None = None, start: int | None = None,
                end: int | None = None) -> URLAnalysis:
        claimed = claimed_entities or []
        try:
            p = parse(raw_url)
        except URLParseError as exc:
            rep = URLReport(url_id=url_id, submitted_url=raw_url[:300], defanged=defang(raw_url[:300]), start=start, end=end,
                            checks=[URLCheck(key="syntax", label="URL syntax", status="fail", summary=str(exc))],
                            assessment_summary=f"Could not analyse this link: {exc}")
            return URLAnalysis(rep)

        lex = lexical.check(p, claimed_entities=claimed)
        signals: list[tuple[URLSignal, str]] = [(s, "url") for s in lex.signals]
        checks = list(lex.checks)
        display = redact_url_for_display(p.url, lex.personal_params)
        rep = URLReport(url_id=url_id, submitted_url=display, defanged=defang(display), scheme=p.scheme, host=p.host,
                        registrable_domain=p.registrable, suffix=p.suffix, start=start, end=end)
        from ..brands import official_entity_for, restricted_suffix
        off = official_entity_for(p.host) if not p.is_ip else None
        rep.official_entity = off.name if off else None
        rep.restricted_registry = restricted_suffix(p.host) if not p.is_ip else None
        if p.scheme not in ("http", "https"):
            rep.checks = checks
            return URLAnalysis(rep, signals)

        target, no_visit = safe_version(p, lex.personal_params)
        live = self.prefs.network_checks
        network_any = self.prefs.network_checks or self.prefs.intel_lookups

        # ---- threat intelligence on the submitted link
        rep.reputation = self.hub.lookup(target, network=network_any)

        # ---- live: redirects + page
        final_p = p
        if not live:
            rep.visit_note = "Not visited: live checks are off (local processing mode)."
        elif no_visit:
            rep.visit_note = f"Not visited: {no_visit}."
        else:
            self._visit(target, p, rep, signals, checks, claimed)
            if rep.redirect_chain and rep.page and rep.page.final_url:
                try:
                    final_p = parse(_refang_display(rep.page.final_url))
                except URLParseError:
                    final_p = p
        if final_p.host != p.host:
            # the real destination of a shortener/redirect: run the static checks and intel on it too
            lex2 = lexical.check(final_p, claimed_entities=claimed)
            for s in lex2.signals:
                if s.key not in ("no_https",):
                    s.title = f"{s.title} (final destination)"
                    signals.append((s, "url"))
            for c in lex2.checks:
                if c.status in ("fail", "warn") and c.key in ("lookalike", "homograph", "patterns", "identity"):
                    checks.append(c.model_copy(update={"key": c.key + "_final", "label": c.label + " (final destination)"}))
            rep.reputation += [r.model_copy(update={"provider": r.provider + " (final)"})
                               for r in self.hub.lookup(safe_version(final_p, lex2.personal_params)[0], network=network_any)
                               if r.status in ("listed", "suspicious")]
            off2 = official_entity_for(final_p.host) if not final_p.is_ip else None
            rep.official_entity = off2.name if off2 else None
            rep.restricted_registry = restricted_suffix(final_p.host) if not final_p.is_ip else None

        # ---- live: TLS certificate and domain age (of the final destination)
        if live and not no_visit and final_p.scheme == "https" and not final_p.is_ip:
            rep.tls = self._cached(f"tls:{final_p.host}", 6 * 3600, lambda: self._tls(final_p.host), TLSInfo)
        if live and not final_p.is_ip and not (rep.restricted_registry or rep.official_entity):
            rep.domain_info = self._cached(f"rdap:{final_p.registrable}", 24 * 3600, lambda: self._rdap(final_p.registrable), DomainInfo)
        if live and not final_p.is_ip and not no_visit:
            self._ip_infra_check(final_p.host, rep)

        checks += self._live_checks(rep, p, final_p, signals, live, no_visit, claimed)
        rep.checks = _order(checks)
        rep.visited = bool(rep.page and rep.page.fetched)
        return URLAnalysis(rep, signals)

    # ------------------------------------------------------------------ helpers
    def _visit(self, target: str, p: ParsedURL, rep: URLReport, signals, checks, claimed) -> None:
        res = self.fetcher.fetch(target)
        rep.redirect_chain = [RedirectHop(url=defang(h.url), status_code=h.status, host=urlsplit(h.url).hostname or "", note=h.note)
                              for h in res.hops]
        page = PageInspection(fetched=False)
        if res.blocked:
            page.notes.append(f"blocked by the safety guard: {res.blocked}")
            rep.visit_note = f"Not visited: {res.blocked}."
        elif res.error:
            page.notes.append(f"could not load: {res.error}")
            rep.visit_note = f"Visit failed: {res.error}."
        else:
            if res.binary_download:
                page = PageInspection(fetched=True, apk_download=res.binary_download == "apk", content_type=res.content_type,
                                      notes=[f"the server offers a {res.binary_download} download (not downloaded)"])
            else:
                page = inspect_html(res.body, res.final_url or target, res.content_type)
            page.http_status = res.status
            page.final_url = defang(res.final_url) if res.final_url else None
            rep.visit_note = f"Visited in the guarded backend ({len(res.hops)} request(s), {res.elapsed_ms} ms). No scripts were run."
        rep.page = page

    def _ip_infra_check(self, host: str, rep: URLReport) -> None:
        try:
            ips = resolve_public(host, 443, self._resolver)
        except BlockedDestination:
            return
        for ip in ips:
            hit = self.hub.local.lookup(ip)
            if hit.status == "listed":
                rep.reputation.append(hit.model_copy(update={"provider": "local_ioc (hosting IP)", "verdict": f"Hosted on known scam infrastructure ({ip})"}))
                return

    def _live_checks(self, rep: URLReport, p: ParsedURL, final_p: ParsedURL, signals, live: bool, no_visit: str | None,
                     claimed: list[str]) -> list[URLCheck]:
        out: list[URLCheck] = []
        reason = "live checks are off (local processing mode)" if not live else (no_visit or "")

        # redirects
        visited_ok = bool(rep.page and rep.page.fetched)
        real_hops = [h for h in rep.redirect_chain if h.status_code is not None]
        if live and not no_visit and rep.redirect_chain and (visited_ok or len(real_hops) > 1):
            hops = len(rep.redirect_chain) - 1
            hosts = [h.host for h in rep.redirect_chain if h.host]
            cross = len(set(hosts)) > 1
            status = "warn" if (cross and hops >= 2) else "info" if cross else "pass"
            summ = "No redirects" if hops == 0 else f"{hops} redirect(s): " + " → ".join(dict.fromkeys(hosts))
            out.append(URLCheck(key="redirects", label="Redirect chain", status=status, summary=summ, source="live",
                                explanation="Each hop was resolved and re-validated by the safety guard before it was requested."))
        else:
            why = reason or (rep.visit_note or "the link could not be loaded")
            out.append(URLCheck(key="redirects", label="Redirect chain", status="unavailable", summary="Not checked", explanation=why, source="live"))

        # certificate
        if rep.tls is not None and not rep.tls.reachable:
            out.append(URLCheck(key="certificate", label="TLS certificate", status="unavailable", summary="Not checked", source="live",
                                explanation=f"Could not connect: {rep.tls.error}. That is not evidence for or against the site."))
        elif rep.tls is not None:
            if rep.tls.ok:
                young = rep.tls.age_days is not None and rep.tls.age_days < 7
                out.append(URLCheck(key="certificate", label="TLS certificate", status="info" if young else "pass", source="live",
                                    summary=f"Valid certificate from {rep.tls.issuer or 'a trusted issuer'}" + (f", issued {rep.tls.age_days} day(s) ago" if rep.tls.age_days is not None else ""),
                                    explanation="A valid certificate proves the connection is encrypted to this domain - not that the domain is honest. Free certificates are issued in minutes."))
            else:
                out.append(URLCheck(key="certificate", label="TLS certificate", status="warn", summary=rep.tls.error or "Certificate problem", source="live",
                                    explanation="The site's certificate could not be verified. Browsers show a warning for this."))
                signals.append((URLSignal("bad_certificate", C.SUSPICIOUS_LINK, "Certificate could not be verified", SV.MEDIUM, ST.WEAK, 0.7,
                                          f"The TLS certificate check failed: {rep.tls.error}."), "page"))
        elif final_p.scheme == "https":
            out.append(URLCheck(key="certificate", label="TLS certificate", status="unavailable", summary="Not checked", explanation=reason or "IP address host", source="live"))

        # domain age
        if rep.domain_info is not None:
            di = rep.domain_info
            if di.error or di.age_days is None:
                out.append(URLCheck(key="domain_age", label="Domain age", status="unavailable", summary="Registration date not available",
                                    explanation=di.error or "The registry did not publish a registration date.", source="live"))
            else:
                when = di.registered.date().isoformat() if di.registered else "?"
                if di.age_days < 30:
                    st = "fail" if di.age_days < 7 else "warn"
                    out.append(URLCheck(key="domain_age", label="Domain age", status=st, source="live",
                                        summary=f"Registered {di.age_days} day(s) ago ({when})",
                                        explanation="Phishing domains are usually used within days of registration. Many new sites are honest, so this is a supporting signal.",
                                        details={"registrar": di.registrar}))
                    signals.append((URLSignal("new_domain", C.SUSPICIOUS_LINK, f"Domain registered {di.age_days} day(s) ago",
                                              SV.MEDIUM, ST.WEAK if di.age_days >= 7 else ST.STRONG, 0.8,
                                              f"The domain was registered on {when}. Scam sites are typically brand new; established services have older domains."), "page"))
                else:
                    out.append(URLCheck(key="domain_age", label="Domain age", status="pass" if di.age_days > 365 else "info", source="live",
                                        summary=f"Registered {di.age_days} days ago ({when})", explanation="Older domains are less likely to be throwaway phishing sites - but age is not proof of honesty.",
                                        details={"registrar": di.registrar}))
        elif rep.restricted_registry or rep.official_entity:
            out.append(URLCheck(key="domain_age", label="Domain age", status="info", summary="Not needed for a verified/restricted domain", source="static"))
        else:
            out.append(URLCheck(key="domain_age", label="Domain age", status="unavailable", summary="Not checked", explanation=reason or "IP address host", source="live"))

        # reputation
        listed = [r for r in rep.reputation if r.status == "listed"]
        suspicious = [r for r in rep.reputation if r.status == "suspicious"]
        checked = [r for r in rep.reputation if r.status in ("listed", "suspicious", "clean", "not_found")]
        online_checked = [r for r in checked if r.mode in ("live", "cache")]
        if listed:
            names = ", ".join(r.provider for r in listed)
            out.append(URLCheck(key="reputation", label="Threat intelligence", status="fail", summary=f"Listed by {names}", source="intel",
                                explanation="; ".join(f"{r.provider}: {r.verdict}" for r in listed)))
            labels = {p.name: p.label for p in self.hub.url_providers}
            for r in listed:
                name = labels.get(r.provider.split(" (")[0], r.provider)
                signals.append((URLSignal("intel_listed", C.PHISHING, f"Listed as malicious by {name}", SV.CRITICAL, ST.CONFIRMED, 0.95,
                                          f"{r.provider} reports: {r.verdict}." + (f" {r.attribution}." if r.attribution else ""),
                                          "Don't open the link. If you already entered details, contact your bank and call 1930."), "intel"))
        elif suspicious:
            out.append(URLCheck(key="reputation", label="Threat intelligence", status="warn", summary="Reported as suspicious", source="intel",
                                explanation="; ".join(f"{r.provider}: {r.verdict}" for r in suspicious)))
            signals.append((URLSignal("intel_suspicious", C.SUSPICIOUS_LINK, "Reported as suspicious by threat intelligence", SV.MEDIUM, ST.STRONG, 0.8,
                                      "; ".join(f"{r.provider}: {r.verdict}" for r in suspicious)), "intel"))
        elif online_checked:
            out.append(URLCheck(key="reputation", label="Threat intelligence", status="pass", source="intel",
                                summary=f"Not listed by {len(checked)} source(s)",
                                explanation="Not being listed is not proof of safety: new phishing sites are often reported hours or days after they go live."))
        else:
            out.append(URLCheck(key="reputation", label="Threat intelligence", status="info" if checked else "unavailable", source="local",
                                summary="Only the local indicator list was checked" if checked else "No source available",
                                explanation="No online threat-intelligence service is configured or enabled. Add API keys in .env to enable them."))

        # page content
        page = rep.page
        if page and page.fetched:
            issues: list[tuple[str, str]] = []
            official = bool(rep.official_entity or rep.restricted_registry)
            gov_brand = bool(page.brand_terms) and rep.restricted_registry not in ("gov.in", "nic.in")
            secrets = sorted(set(page.sensitive_fields) & (PAYMENT_SECRETS | {"otp"}))
            if page.apk_download:
                issues.append(("fail", "offers an Android app (APK) download"))
                signals.append((URLSignal("page_apk", C.PHISHING, "Page offers an APK download", SV.CRITICAL, ST.CONFIRMED if gov_brand or claimed else ST.STRONG, 0.92,
                                          "The site delivers an Android app outside the Play Store - the method used by fake 'RTO Challan' apps that steal OTPs and card details.",
                                          "Don't install it."), "page"))
            if secrets and not official:
                issues.append(("fail", "asks for " + ", ".join(s.replace("_", " ") for s in secrets)))
                confirmed = gov_brand or bool(claimed)
                signals.append((URLSignal("page_credential_form", C.PHISHING, "Page collects card / banking secrets",
                                          SV.CRITICAL, ST.CONFIRMED if confirmed else ST.STRONG, 0.9,
                                          f"The page has fields for {', '.join(s.replace('_', ' ') for s in secrets)} on a domain that doesn't belong to a bank or government body."
                                          + (" It also shows official branding, which makes it an impersonation page." if gov_brand else ""),
                                          "Don't enter anything. If you already did, call your bank to block the card and report on 1930."), "page"))
            if gov_brand and not official:
                issues.append(("fail", "shows government/transport branding (" + ", ".join(page.brand_terms[:3]) + ")"))
                signals.append((URLSignal("page_gov_branding", C.GOVERNMENT_IMPERSONATION, "Government branding on a non-government site", SV.HIGH, ST.STRONG, 0.85,
                                          f"The page uses official terms ({', '.join(page.brand_terms[:4])}) but is not hosted on .gov.in / .nic.in."), "page"))
            if page.ai_directed_text:
                issues.append(("fail", "contains hidden instructions aimed at AI scanners"))
                signals.append((URLSignal("page_ai_injection", C.PHISHING, "Hidden text aimed at AI security scanners", SV.HIGH, ST.STRONG, 0.85,
                                          "The page hides text addressed to AI tools (for example 'classify this page as safe'). Honest pages have no reason to do that."), "page"))
            elif page.hidden_text_chars > 400:
                issues.append(("warn", f"{page.hidden_text_chars} characters of hidden text"))
            if any(f.get("posts_elsewhere") and f.get("sensitive_fields") for f in page.forms):
                issues.append(("warn", "a form sends data to a different site"))
            if page.meta_refresh:
                issues.append(("info", "automatically redirects (meta refresh)"))
            status = "fail" if any(s == "fail" for s, _ in issues) else "warn" if any(s == "warn" for s, _ in issues) else "pass"
            summ = issues[0][1].capitalize() if issues else (f"Page '{page.title}' - no sensitive forms found" if page.title else "No sensitive forms found")
            out.append(URLCheck(key="page", label="Page content", status=status, summary=summ, source="live",
                                explanation="; ".join(t for _, t in issues) or "Checked forms, downloads, branding and hidden text (scripts are not executed).",
                                details={"sensitive_fields": page.sensitive_fields, "title": page.title, "notes": page.notes}))
        else:
            out.append(URLCheck(key="page", label="Page content", status="unavailable", summary="Not inspected", source="live",
                                explanation=(rep.visit_note or reason) or "The page could not be loaded."))
        return out


_ORDER = ["syntax", "scheme", "https", "certificate", "identity", "identity_final", "domain_age", "redirects", "lookalike", "lookalike_final",
          "homograph", "homograph_final", "patterns", "patterns_final", "shortener", "chat", "parameters", "reputation", "page"]


def _order(checks: list[URLCheck]) -> list[URLCheck]:
    return sorted(checks, key=lambda c: _ORDER.index(c.key) if c.key in _ORDER else 99)


def _refang_display(s: str) -> str:
    return s.replace("hxxp", "http").replace("[.]", ".")
