"""Live link inspection, built to be safe to point at hostile URLs.

The fetcher is the part of TrustGuard that an attacker controls the input of, so it is hardened like an SSRF target:

* only ``http``/``https`` on allowed ports (80/443 by default);
* every hostname is resolved by us and *every* returned address must be public (``ipaddress.is_global``) - private,
  loopback, link-local, CGNAT, multicast and reserved ranges are refused, including IPv4-mapped IPv6;
* the TCP connection is made to the exact address we validated (``GuardedBackend``), while TLS still verifies the
  certificate for the hostname - so DNS rebinding between "check" and "connect" cannot redirect us inside the network;
* redirects are followed manually, one hop at a time, and each hop is re-validated; at most ``max_redirects``;
* GET only, no cookies kept, no JavaScript executed, body capped at ``max_page_bytes``, strict timeouts;
* APK/executable responses are recorded from their headers and never downloaded.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from ..schemas import DomainInfo, TLSInfo

Resolver = Callable[..., list]


class BlockedDestination(Exception):
    """The URL (or a redirect hop) points somewhere TrustGuard refuses to connect to."""


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:  # pragma: no cover
        return ssl.create_default_context()


def check_ip(ip: str) -> None:
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not addr.is_global or addr.is_multicast:
        raise BlockedDestination(f"address {addr} is not a public internet address")


def _literal_ip(host: str) -> str | None:
    """'127.0.0.1', '[::1]', and the integer/hex spellings browsers accept ('2130706433', '0x7f000001')."""
    h = host.strip("[]").lower()
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        if h.isdigit():
            return str(ipaddress.ip_address(int(h)))
        if h.startswith("0x"):
            return str(ipaddress.ip_address(int(h, 16)))
    except ValueError:
        return None
    return None


def resolve_public(host: str, port: int, resolver: Resolver = socket.getaddrinfo) -> list[str]:
    host = host.strip("[]")
    literal = _literal_ip(host)
    if literal is not None:
        check_ip(literal)
        return [literal]
    try:
        infos = resolver(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BlockedDestination(f"could not resolve {host} ({exc.strerror or exc})") from None
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise BlockedDestination(f"{host} has no address")
    for ip in ips:
        check_ip(ip)                     # refuse if ANY address is internal (split-horizon / rebinding tricks)
    return ips


class GuardedBackend(httpcore.SyncBackend):
    """httpcore network backend that only ever connects to validated public addresses."""

    def __init__(self, allowed_ports: tuple[int, ...] = (80, 443), resolver: Resolver = socket.getaddrinfo):
        self.allowed_ports = allowed_ports
        self.resolver = resolver

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if port not in self.allowed_ports:
            raise BlockedDestination(f"port {port} is not allowed")
        last: Exception | None = None
        for ip in resolve_public(host, port, self.resolver)[:2]:
            try:
                return super().connect_tcp(ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last or httpcore.ConnectError("connection failed")


def guarded_transport(allowed_ports: tuple[int, ...] = (80, 443), resolver: Resolver = socket.getaddrinfo) -> httpx.HTTPTransport:
    transport = httpx.HTTPTransport(verify=_ssl_context(), retries=0, trust_env=False)
    # httpx does not expose the network backend; swap in a pool that uses ours (same arguments httpx uses itself).
    transport._pool = httpcore.ConnectionPool(ssl_context=_ssl_context(), max_connections=4, max_keepalive_connections=0,
                                              retries=0, network_backend=GuardedBackend(allowed_ports, resolver))
    return transport


@dataclass
class Hop:
    url: str
    status: int | None
    location: str | None = None
    note: str = ""


@dataclass
class FetchResult:
    requested_url: str
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    content_type: str = ""
    binary_download: str | None = None     # "apk" / "executable" when the server offers a file
    blocked: str | None = None
    error: str | None = None
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None and self.blocked is None and self.status is not None


_REDIRECT = {301, 302, 303, 307, 308}
_APK_TYPES = ("application/vnd.android.package-archive",)
_EXE_TYPES = ("application/x-msdownload", "application/x-msdos-program", "application/x-dosexec", "application/java-archive")


class SafeFetcher:
    def __init__(self, *, timeout_s: float = 8.0, max_redirects: int = 5, max_bytes: int = 1_500_000,
                 allowed_ports: tuple[int, ...] = (80, 443), user_agent: str = "TrustGuard/0.1",
                 transport: httpx.BaseTransport | None = None, resolver: Resolver = socket.getaddrinfo, total_budget_s: float = 20.0):
        self.timeout_s, self.max_redirects, self.max_bytes = timeout_s, max_redirects, max_bytes
        self.allowed_ports, self.user_agent, self.total_budget_s = allowed_ports, user_agent, total_budget_s
        self.resolver = resolver
        self._transport = transport

    def _client(self) -> httpx.Client:
        transport = self._transport or guarded_transport(self.allowed_ports, self.resolver)
        return httpx.Client(transport=transport, follow_redirects=False, trust_env=False, timeout=self.timeout_s,
                            headers={"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
                                     "Accept-Language": "en-IN,en;q=0.9,hi;q=0.8"})

    def _validate(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise BlockedDestination(f"scheme '{parts.scheme}' is not allowed")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if port not in self.allowed_ports:
            raise BlockedDestination(f"port {port} is not allowed")
        if not parts.hostname:
            raise BlockedDestination("no host")
        literal = _literal_ip(parts.hostname)
        if literal is not None:
            check_ip(literal)                        # literal / decimal / hex IPs are checked even without DNS
        elif self._transport is None:                # with an injected (test) transport, DNS is not used
            resolve_public(parts.hostname, port, self.resolver)

    def fetch(self, url: str) -> FetchResult:
        res = FetchResult(requested_url=url)
        start = time.monotonic()
        current = url
        try:
            with self._client() as client:
                for _ in range(self.max_redirects + 1):
                    if time.monotonic() - start > self.total_budget_s:
                        res.error = "time budget exceeded"
                        break
                    try:
                        self._validate(current)
                    except BlockedDestination as exc:
                        res.blocked = str(exc)
                        res.hops.append(Hop(current, None, note=f"blocked: {exc}"))
                        break
                    with client.stream("GET", current) as resp:
                        loc = resp.headers.get("location")
                        if resp.status_code in _REDIRECT and loc:
                            nxt = urljoin(current, loc)
                            res.hops.append(Hop(current, resp.status_code, nxt))
                            current = nxt
                            continue
                        res.hops.append(Hop(current, resp.status_code))
                        res.final_url, res.status = current, resp.status_code
                        res.headers = {k.lower(): v for k, v in resp.headers.items()}
                        ctype = res.headers.get("content-type", "").split(";")[0].strip().lower()
                        res.content_type = ctype
                        disp = res.headers.get("content-disposition", "").lower()
                        path = urlsplit(current).path.lower()
                        if ctype in _APK_TYPES or path.endswith(".apk") or ".apk" in disp:
                            res.binary_download = "apk"
                        elif ctype in _EXE_TYPES or path.endswith((".exe", ".msi", ".scr")):
                            res.binary_download = "executable"
                        else:
                            buf = bytearray()
                            for chunk in resp.iter_bytes():
                                buf.extend(chunk)
                                if len(buf) >= self.max_bytes:
                                    res.truncated = True
                                    break
                            res.body = bytes(buf[: self.max_bytes])
                        break
                else:
                    res.error = f"more than {self.max_redirects} redirects"
        except BlockedDestination as exc:
            res.blocked = str(exc)
        except httpx.TimeoutException:
            res.error = "timed out"
        except (httpx.HTTPError, httpcore.ProtocolError, ssl.SSLError, OSError) as exc:
            res.error = _short_error(exc)
        res.elapsed_ms = int((time.monotonic() - start) * 1000)
        return res


def _short_error(exc: Exception) -> str:
    text = str(exc) or type(exc).__name__
    if "CERTIFICATE_VERIFY_FAILED" in text:
        return "TLS certificate could not be verified"
    return text.splitlines()[0][:160]


# ----------------------------------------------------------------------------------------------- TLS certificate
def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


def probe_tls(host: str, port: int = 443, timeout_s: float = 6.0, resolver: Resolver = socket.getaddrinfo) -> TLSInfo:
    try:
        ip = resolve_public(host, port, resolver)[0]
        ctx = _ssl_context()
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
    except BlockedDestination as exc:
        return TLSInfo(ok=False, reachable=False, error=str(exc))
    except ssl.SSLCertVerificationError as exc:
        return TLSInfo(ok=False, error=f"certificate not trusted: {exc.verify_message or exc.reason}")
    except ssl.SSLError as exc:
        return TLSInfo(ok=False, error=f"TLS handshake failed: {_short_error(exc)}")
    except OSError as exc:                                  # DNS failure, refused, timed out: no evidence either way
        return TLSInfo(ok=False, reachable=False, error=_short_error(exc))
    issuer = {k: v for part in cert.get("issuer", ()) for k, v in part}
    subject = {k: v for part in cert.get("subject", ()) for k, v in part}
    nb, na = _parse_cert_time(cert.get("notBefore")), _parse_cert_time(cert.get("notAfter"))
    age = (datetime.now(timezone.utc) - nb).days if nb else None
    return TLSInfo(ok=True, issuer=issuer.get("organizationName") or issuer.get("commonName"), subject=subject.get("commonName"),
                   not_before=nb, not_after=na, age_days=age, san_count=len(cert.get("subjectAltName", ())))


# ----------------------------------------------------------------------------------------------- RDAP (domain age)
def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_rdap(data: dict) -> DomainInfo:
    reg = next((_iso(e.get("eventDate")) for e in data.get("events", []) if e.get("eventAction") == "registration"), None)
    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
            registrar = next((item[3] for item in vcard if item and item[0] == "fn"), None) or ent.get("handle")
    age = (datetime.now(timezone.utc) - reg).days if reg else None
    return DomainInfo(source="rdap", registered=reg, age_days=age, registrar=registrar, status=list(data.get("status", []))[:6])


def lookup_rdap(domain: str, timeout_s: float = 8.0, transport: httpx.BaseTransport | None = None) -> DomainInfo:
    """Registration date via RDAP (rdap.org redirects to the registry responsible for the TLD)."""
    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=True, transport=transport,
                          headers={"Accept": "application/rdap+json, application/json"}) as client:
            r = client.get(f"https://rdap.org/domain/{domain}")
        if r.status_code == 404:
            return DomainInfo(error="the registry has no public RDAP record for this domain")
        if r.status_code != 200:
            return DomainInfo(error=f"RDAP lookup returned HTTP {r.status_code}")
        return parse_rdap(r.json())
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        return DomainInfo(error=f"RDAP lookup failed: {_short_error(exc)}")
