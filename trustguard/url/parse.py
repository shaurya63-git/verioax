"""Finding, normalising, defanging and parsing URLs.

The public-suffix list is the bundled snapshot that ships with ``tldextract`` (no network fetch at runtime), with
private suffixes enabled so that free-hosting platforms (``web.app``, ``pages.dev``, ``github.io`` ...) count as
suffixes: in ``parivahan-fine.web.app`` the part a scammer chose is ``parivahan-fine``.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


# Bare domains (no scheme, no www, no path) are only accepted with these common suffixes; this avoids reading
# file names such as "photo.zip" or "notes.md" as links.
_BARE_OK = {
    "com", "in", "net", "org", "info", "co", "co.in", "org.in", "net.in", "gov.in", "nic.in", "bank.in", "io", "me", "app", "xyz", "top",
    "vip", "icu", "cc", "site", "online", "live", "shop", "club", "link", "ly", "gd", "to", "sbs", "cfd", "cyou", "buzz", "click",
    "store", "website", "space", "tech", "pro", "biz", "ws", "su", "ru", "cn", "lol", "rest", "bond", "life", "work", "world",
}

_SCHEME_URL = re.compile(r"(?i)\b(?:https?|hxxps?|h\*\*ps?)(?:://|\[://\]|\[:\]//)[^\s<>\"'`]+")
_WWW_URL = re.compile(r"(?i)(?<![\w@./-])www(?:\.|\[\.\]|\(\.\))[^\s<>\"'`]+")
_BARE = re.compile(r"(?i)(?<![\w@./:-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]))+[a-z]{2,24}(?::\d{2,5})?(?:/[^\s<>\"'`]*)?")
_TRAILING = ".,;:!?)]}'\"…"


def refang(s: str) -> str:
    s = re.sub(r"(?i)\bhxxp", "http", s)
    s = re.sub(r"(?i)\bh\*\*p", "http", s)
    s = s.replace("[://]", "://").replace("[:]//", "://").replace("[:]", ":")
    s = re.sub(r"(?i)\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", s)
    return s


def defang(url: str) -> str:
    """hxxps://example[.]com/path - safe to display, can't be clicked or auto-linked."""
    s = re.sub(r"(?i)^http", "hxxp", url)
    parts = urlsplit(s if "://" in s else "hxxp://" + s)
    host = (parts.hostname or "").replace(".", "[.]")
    port = f":{parts.port}" if parts.port else ""
    rest = parts.path + (("?" + parts.query) if parts.query else "")
    scheme = parts.scheme or "hxxp"
    return f"{scheme}://{host}{port}{rest}" if "://" in url or url.lower().startswith("http") else f"{host}{port}{rest}"


@dataclass
class FoundURL:
    raw: str
    url: str          # refanged, scheme added when it was missing
    start: int
    end: int
    had_scheme: bool


def extract_urls(text: str, limit: int = 10) -> list[FoundURL]:
    found: list[FoundURL] = []
    taken: list[tuple[int, int]] = []

    def add(m: re.Match, kind: str) -> None:
        raw = m.group()
        while raw and raw[-1] in _TRAILING:
            if raw[-1] == ")" and raw.count("(") >= raw.count(")"):
                break
            raw = raw[:-1]
        s, e = m.start(), m.start() + len(raw)
        if any(s < te and ts < e for ts, te in taken) or len(raw) < 4:
            return
        url = refang(raw)
        if kind == "bare":
            host = re.split(r"[/:?#]", url, maxsplit=1)[0]
            ext = _extractor()(host)
            has_path = "/" in url
            if not ext.suffix or not ext.domain or (not has_path and ext.suffix.lower() not in _BARE_OK):
                return
        had_scheme = kind == "scheme"
        if not had_scheme:
            url = "http://" + url
        taken.append((s, e))
        found.append(FoundURL(raw, url, s, e, had_scheme))

    for m in _SCHEME_URL.finditer(text):
        add(m, "scheme")
    for m in _WWW_URL.finditer(text):
        add(m, "www")
    for m in _BARE.finditer(text):
        add(m, "bare")
    found.sort(key=lambda f: f.start)
    return found[:limit]


@dataclass
class ParsedURL:
    url: str
    scheme: str
    host: str                 # lower-case, ASCII (punycode) form
    unicode_host: str         # decoded form when the host is punycode
    port: int | None
    path: str
    query: str
    userinfo: str
    registrable: str          # e.g. parivahan.gov.in, echallx.vip
    subdomain: str
    domain_label: str         # the label just left of the suffix
    suffix: str
    is_ip: bool
    is_punycode: bool


class URLParseError(ValueError):
    pass


def parse(url: str) -> ParsedURL:
    url = refang(url.strip())
    if not url:
        raise URLParseError("empty URL")
    if re.match(r"(?i)^(?:javascript|data|vbscript|file):", url):
        scheme = url.split(":", 1)[0].lower()
        return ParsedURL(url, scheme, "", "", None, "", "", "", "", "", "", "", False, False)
    if "://" not in url:
        url = "http://" + url
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise URLParseError(f"malformed URL: {exc}") from None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise URLParseError(f"unsupported scheme '{scheme}'")
    host = (parts.hostname or "").rstrip(".")
    if not host or " " in host or len(host) > 253:
        raise URLParseError("missing or invalid host")
    unicode_host = host
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        ascii_host = host.lower()
    if "xn--" in ascii_host:
        try:
            unicode_host = ascii_host.encode("ascii").decode("idna")
        except UnicodeError:
            unicode_host = ascii_host
    is_ip = _is_ip(ascii_host)
    if is_ip:
        reg, sub, label, suffix = ascii_host, "", ascii_host, ""
    else:
        ext = _extractor()(ascii_host)
        if not ext.suffix:
            raise URLParseError(f"'{ascii_host}' has no recognised top-level domain")
        reg = ".".join(p for p in (ext.domain, ext.suffix) if p)
        sub, label, suffix = ext.subdomain, ext.domain, ext.suffix
    userinfo = ""
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0]
    return ParsedURL(url=url, scheme=scheme, host=ascii_host, unicode_host=unicode_host, port=port, path=parts.path or "/",
                     query=parts.query, userinfo=userinfo, registrable=reg, subdomain=sub, domain_label=label, suffix=suffix,
                     is_ip=is_ip, is_punycode="xn--" in ascii_host)


def _is_ip(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # decimal / hex / octal IPv4 tricks: http://3232235777/ or http://0x7f000001/
    return bool(re.fullmatch(r"(?:0x[0-9a-f]+|\d{8,10})", h))
