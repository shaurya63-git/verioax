"""Static URL checks: everything that can be learned from the URL string alone, without visiting it.

Each check produces a ``URLCheck`` row for the report (green / amber / red / grey) and, when it is a risk signal, a
``URLSignal`` that becomes an explainable finding in the overall score.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from rapidfuzz.distance import DamerauLevenshtein
from rapidfuzz.fuzz import partial_ratio, ratio

from .. import brands as B
from ..schemas import ScamCategory as C
from ..schemas import Severity as SV
from ..schemas import Strength as ST
from ..schemas import URLCheck
from .parse import ParsedURL

SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.ly", "is.gd", "v.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly",
    "buff.ly", "rebrand.ly", "s.id", "t.co", "goo.gl", "lnkd.in", "bl.ink", "short.gy", "soo.gd", "surl.li", "clck.ru",
    "u.to", "shorturl.gg", "qr.ae", "tr.im", "x.co", "cli.re", "rebrandly.com", "shrtco.de", "da.gd",
}
CHAT_LINKS = {"wa.me": "WhatsApp chat", "api.whatsapp.com": "WhatsApp chat", "chat.whatsapp.com": "WhatsApp group",
              "t.me": "Telegram chat", "telegram.me": "Telegram chat"}
RISKY_TLDS = {"vip", "icu", "cc", "top", "xyz", "shop", "click", "buzz", "cyou", "sbs", "cfd", "rest", "lol", "quest", "bond",
              "cam", "mom", "gq", "ml", "tk", "cf", "ga", "zip", "mov", "monster", "fun", "work", "support", "live", "online", "site"}
FREE_HOSTING = {"web.app", "firebaseapp.com", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "github.io", "gitlab.io",
                "glitch.me", "herokuapp.com", "onrender.com", "repl.co", "replit.app", "blogspot.com", "wixsite.com", "weebly.com",
                "000webhostapp.com", "ngrok-free.app", "ngrok.io", "trycloudflare.com", "azurewebsites.net", "appspot.com", "r2.dev",
                "surge.sh", "godaddysites.com", "carrd.co", "framer.app", "webflow.io"}
DANGEROUS_EXT = {".apk": "Android app (APK)", ".exe": "Windows program", ".msi": "Windows installer", ".scr": "Windows screensaver",
                 ".bat": "batch script", ".cmd": "command script", ".jar": "Java program", ".vbs": "VBScript", ".ps1": "PowerShell script"}
ARCHIVE_EXT = {".zip", ".rar", ".7z"}

# Characters from other scripts that render like Latin letters (subset of Unicode TR39 confusables).
CONFUSABLES = str.maketrans({
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y",
    "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "ӏ": "l", "ԛ": "q", "ԝ": "w", "һ": "h", "ɡ": "g", "ո": "n",
    "ս": "u", "օ": "o", "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "χ": "x", "υ": "u", "ε": "e", "τ": "t",
    "ı": "i", "ł": "l", "ɑ": "a", "ɩ": "i", "ʟ": "l", "ᴏ": "o", "ⅰ": "i", "ⅼ": "l",
})


@dataclass
class URLSignal:
    key: str
    category: C
    title: str
    severity: SV
    strength: ST
    confidence: float
    explanation: str
    action: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class LexicalResult:
    checks: list[URLCheck]
    signals: list[URLSignal]
    personal_params: list[str]          # query parameter names that carry personal data or tracking ids
    lookalike_of: list[str]             # entity keys this URL imitates
    shortener: bool
    chat_link: str | None


def _skeleton(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).lower()
    return s.translate(CONFUSABLES)


def _scripts(label: str) -> set[str]:
    out = set()
    for ch in label:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0] if name else "UNKNOWN")
    return out


def _tokens(p: ParsedURL) -> list[str]:
    labels = [x for x in (p.subdomain.split(".") if p.subdomain else []) + [p.domain_label] if x and x != "www"]
    toks = []
    for lab in labels:
        toks.append(lab)
        toks.extend(t for t in re.split(r"[-_]", lab) if t and t != lab)
    return toks


_LURE_TOKENS = {"kyc", "update", "verify", "verification", "login", "signin", "secure", "reward", "refund", "challan", "pay", "payment",
                "otp", "blocked", "unblock", "support", "help", "care", "bonus", "gift", "claim", "fine", "pending", "alert"}


def _lookalikes(p: ParsedURL, host_for_compare: str) -> list[tuple[B.Entity, str, str, int]]:
    """(entity, kind, detail, distance) for every brand this host imitates.

    kind: 'deceptive_subdomain' (official domain used as a prefix), 'typo' (near-miss spelling), 'contains' (brand word inside
    an unofficial domain). distance is the edit distance for typos (0 otherwise).
    """
    hits: list[tuple[B.Entity, str, str, int]] = []
    toks = _tokens(p)
    labels = [x for x in (p.subdomain.split(".") if p.subdomain else []) + [p.domain_label] if x]
    for e in B.ENTITIES:
        if B.host_is_official_for(p.host, e):
            continue
        hit = None
        for d in e.domains:                                         # parivahan.gov.in.verify-now.xyz
            if (f"{d}." in host_for_compare or f"{d}-" in host_for_compare) and not host_for_compare.endswith(d):
                hit = (e, "deceptive_subdomain", f"contains '{d}' but is registered as '{p.registrable}'", 0)
                break
        for kw in e.keywords if hit is None else ():
            if kw in ("gov", "gov-in", "govin"):
                continue                                            # handled by the government-lookalike check
            found = kw in toks if len(kw) <= 3 else any(kw in lab for lab in labels)
            if found:
                hit = (e, "contains", f"uses '{kw}' in a domain that {e.name} does not own", 0)
                break
            if not e.fuzzy or len(kw) < 6:
                continue
            for t in toks:
                if t == kw or len(t) < 5 or abs(len(t) - len(kw)) > 4:
                    continue
                dist = DamerauLevenshtein.distance(t, kw)
                if dist <= (1 if len(kw) < 8 else 2) or partial_ratio(kw, t) >= 87 or (len(kw) >= 8 and ratio(kw, t) >= 80):
                    hit = (e, "typo", f"'{t}' is a near-copy of '{kw}'", dist)
                    break
            if hit:
                break
        if hit:
            hits.append(hit)
    return hits


def check(p: ParsedURL, *, claimed_entities: list[str] | None = None) -> LexicalResult:
    checks: list[URLCheck] = []
    signals: list[URLSignal] = []
    claimed = set(claimed_entities or [])

    # ---- 1. scheme / transport
    if p.scheme in ("javascript", "data", "vbscript", "file"):
        checks.append(URLCheck(key="scheme", label="Link type", status="fail", summary=f"'{p.scheme}:' link",
                               explanation="This is not a web address; it runs code or embeds content directly."))
        signals.append(URLSignal("script_scheme", C.SUSPICIOUS_LINK, f"'{p.scheme}:' link", SV.HIGH, ST.STRONG, 0.9,
                                 "Links that start with javascript: or data: run code or show content without a real website behind them."))
        return LexicalResult(checks, signals, [], [], False, None)
    if p.scheme == "https":
        checks.append(URLCheck(key="https", label="HTTPS / TLS", status="pass", summary="Uses HTTPS (encrypted connection)",
                               explanation="HTTPS only means the connection is encrypted. Scam sites use HTTPS too - it says nothing about who runs the site."))
    else:
        checks.append(URLCheck(key="https", label="HTTPS / TLS", status="warn", summary="Not encrypted (plain HTTP)",
                               explanation="Anything typed on this page travels unencrypted. Never enter personal or payment details on an http:// page."))
        signals.append(URLSignal("no_https", C.SUSPICIOUS_LINK, "Unencrypted link (http://)", SV.LOW, ST.WEAK, 0.8,
                                 "The link does not use HTTPS, so anything typed there can be read in transit."))

    # ---- 2. identity: official domain / restricted registry
    official = B.official_entity_for(p.host) if not p.is_ip else None
    registry = B.restricted_suffix(p.host) if not p.is_ip else None
    if official:
        checks.append(URLCheck(key="identity", label="Domain ownership", status="pass", summary=f"Official domain of {official.name}",
                               explanation=f"'{p.registrable}' is on TrustGuard's list of verified domains for {official.name}.",
                               details={"entity": official.key}))
    elif registry:
        checks.append(URLCheck(key="identity", label="Domain ownership", status="pass", summary=B.RESTRICTED_SUFFIXES[registry],
                               explanation=f"Only eligible organisations can register under '.{registry}', so a scammer cannot simply buy this domain.",
                               details={"registry": registry}))
    else:
        checks.append(URLCheck(key="identity", label="Domain ownership", status="info", summary=f"Unverified domain: {p.registrable}",
                               explanation="This domain is not on the list of verified official domains. That alone is not a problem - most of the web isn't - "
                                           "but a message that claims to be from a bank or government office should link to that organisation's own domain."))

    # ---- 3. lookalikes / typosquatting
    host_cmp = _skeleton(p.unicode_host) if p.is_punycode else p.host
    looks = _lookalikes(p, host_cmp) if not (p.is_ip or official or registry) else []
    gov_like = (not registry and not p.is_ip and
                (re.search(r"(?:^|[.-])(?:gov|govt)(?:[.-]|in\b|$)", ".".join(_tokens(p))) is not None or "gov-in" in p.host or "govin" in p.host))
    lookalike_of: list[str] = []
    if looks or gov_like:
        rows = []
        tld_risky = (p.suffix.rsplit(".", 1)[-1] in RISKY_TLDS) or p.suffix in FREE_HOSTING
        lure = bool(_LURE_TOKENS & set(_tokens(p)))
        for e, kind, detail, dist in looks:
            lookalike_of.append(e.key)
            context = e.key in claimed or tld_risky or lure
            if kind == "deceptive_subdomain" or (kind == "typo" and dist <= 1):
                strong = True
            elif kind == "typo":
                strong = context
            else:                                                   # brand word inside an unofficial domain
                strong = context and (e.kind in ("government", "bank", "payments") or e.key in claimed or (tld_risky and lure))
            title = {"typo": f"Lookalike of {e.name}", "deceptive_subdomain": f"Disguised as {e.name}",
                     "contains": f"Uses the name {e.name} in an unofficial domain"}[kind]
            cat = C.GOVERNMENT_IMPERSONATION if e.is_government else C.BANK_IMPERSONATION if e.kind == "bank" else C.BRAND_IMPERSONATION
            why = []
            if e.key in claimed:
                why.append(f"the message claims to be from {e.name}")
            if tld_risky:
                why.append(f"it uses a throwaway ending (.{p.suffix})")
            if lure:
                why.append("it combines the name with words like 'kyc', 'pay' or 'verify'")
            explanation = (f"The domain {detail}. Scammers register names like this so the link looks official at a glance."
                           + (f" It is more suspicious because {', and '.join(why)}." if why else
                              " On its own this can also be a partner, reseller or fan site, so it is reported as a weaker signal."))
            # a near-identical spelling, a disguised subdomain, or the name plus a lure word is critical; the bare name is high
            critical = strong and (kind == "deceptive_subdomain" or (kind == "typo" and dist <= 1) or lure or e.key in claimed)
            sev = SV.CRITICAL if critical else SV.HIGH if strong else SV.MEDIUM
            signals.append(URLSignal(f"lookalike_{kind}", cat, title, sev, ST.STRONG if strong else ST.WEAK,
                                     0.88 if strong else 0.7, explanation, e.verify or "Type the organisation's official address yourself instead.", [detail]))
            rows.append((title, detail))
        if gov_like:
            lookalike_of.append("government_generic")
            signals.append(URLSignal("gov_lookalike", C.GOVERNMENT_IMPERSONATION, "Pretends to be a government domain", SV.CRITICAL, ST.STRONG, 0.9,
                                     f"'{p.registrable}' contains 'gov' but is not under .gov.in. Real Indian government sites end in .gov.in or .nic.in.",
                                     "Only trust government links that end in .gov.in or .nic.in.", [p.registrable]))
            rows.append(("Pretends to be a government domain", f"'{p.registrable}' imitates a .gov.in address"))
        checks.append(URLCheck(key="lookalike", label="Domain similarity", status="fail" if any(s.strength == ST.STRONG for s in signals if s.key.startswith(("lookalike", "gov_"))) else "warn",
                               summary=rows[0][0], explanation="; ".join(f"{t}: {d}" for t, d in rows)))
    elif not (official or registry or p.is_ip) and len(_LURE_TOKENS & set(_tokens(p))) >= 2:
        words = sorted(_LURE_TOKENS & set(_tokens(p)))
        risky = (p.suffix.rsplit(".", 1)[-1] in RISKY_TLDS) or p.suffix in FREE_HOSTING
        checks.append(URLCheck(key="lookalike", label="Domain similarity", status="warn", summary=f"Phishing-style words in the domain ({', '.join(words)})",
                               explanation="The domain is built from words like 'secure', 'login' and 'verify' rather than a brand name - a common pattern for throwaway phishing sites."))
        signals.append(URLSignal("lure_words_domain", C.PHISHING, "Phishing-style words in an unknown domain", SV.MEDIUM, ST.STRONG if risky else ST.WEAK,
                                 0.8 if risky else 0.7, f"'{p.registrable}' combines {', '.join(words)}"
                                 + (f" with a throwaway ending (.{p.suffix})" if risky else "") + ". Legitimate services use their brand name, not generic security words.",
                                 "Don't enter anything on this site.", [p.registrable]))
    elif official or registry:
        checks.append(URLCheck(key="lookalike", label="Domain similarity", status="pass", summary="Matches a verified domain exactly"))
    else:
        checks.append(URLCheck(key="lookalike", label="Domain similarity", status="pass", summary="No resemblance to known brands found",
                               explanation="Compared with the official domains of Indian government services, banks, payment apps and couriers."))

    # ---- 4. homograph / punycode
    if p.is_punycode:
        mixed = any(len(_scripts(lab) - {"DIGIT"}) > 1 for lab in p.unicode_host.split("."))
        skel = _skeleton(p.unicode_host)
        imitates = next((e for e in B.ENTITIES for d in e.domains if skel.endswith(d) or any(k in skel for k in e.keywords if len(k) >= 4)), None)
        if mixed or imitates:
            what = f"imitates {imitates.name}" if imitates else "mixes alphabets"
            checks.append(URLCheck(key="homograph", label="Lookalike characters", status="fail",
                                   summary=f"'{p.unicode_host}' {what}", explanation="The address uses letters from another alphabet that look like Latin letters (a homograph attack).",
                                   details={"punycode": p.host, "reads_as": skel}))
            signals.append(URLSignal("homograph", C.BRAND_IMPERSONATION, "Homograph (lookalike-character) domain", SV.CRITICAL if imitates else SV.HIGH, ST.STRONG, 0.9,
                                     f"'{p.unicode_host}' is written with characters from another alphabet that look like '{skel}'.",
                                     "Don't open it. Type the real address yourself.", [p.host]))
            if imitates:
                lookalike_of.append(imitates.key)
        else:
            checks.append(URLCheck(key="homograph", label="Lookalike characters", status="warn", summary="Internationalised (non-Latin) domain",
                                   explanation=f"Displayed as '{p.unicode_host}'. Legitimate for local-language sites; check it is the site you expect."))
    else:
        checks.append(URLCheck(key="homograph", label="Lookalike characters", status="pass", summary="Plain ASCII domain"))

    # ---- 5. structural patterns
    issues: list[tuple[str, str]] = []           # (status, text)
    if p.is_ip:
        issues.append(("fail", "points to a raw IP address instead of a domain name"))
        signals.append(URLSignal("ip_host", C.SUSPICIOUS_LINK, "Link to a raw IP address", SV.HIGH, ST.STRONG, 0.85,
                                 "Legitimate services use domain names. A bare IP address is typical of throwaway phishing or malware servers."))
    if p.userinfo:
        issues.append(("fail", f"text before '@' ('{p.userinfo}') is ignored by browsers - the real site is {p.host}"))
        signals.append(URLSignal("userinfo_trick", C.PHISHING, "'@' trick hides the real address", SV.HIGH, ST.STRONG, 0.9,
                                 f"Browsers ignore everything before '@' in a link, so '{p.userinfo}@' only pretends to be the destination. The real site is {p.host}."))
    if p.port and p.port not in (80, 443):
        issues.append(("warn", f"uses an unusual port ({p.port})"))
        signals.append(URLSignal("odd_port", C.SUSPICIOUS_LINK, "Unusual port number", SV.LOW, ST.WEAK, 0.7, f"The link uses port {p.port}, which ordinary websites don't."))
    sub_labels = [x for x in p.subdomain.split(".") if x] if p.subdomain else []
    if len(sub_labels) >= 4:
        issues.append(("warn", f"{len(sub_labels)} levels of subdomains"))
        signals.append(URLSignal("deep_subdomains", C.SUSPICIOUS_LINK, "Unusually long chain of subdomains", SV.LOW, ST.WEAK, 0.7,
                                 "Long subdomain chains are used to push the real domain out of view on phone screens."))
    if p.suffix in FREE_HOSTING:
        issues.append(("warn", f"hosted on a free website service ({p.suffix})"))
        signals.append(URLSignal("free_hosting", C.SUSPICIOUS_LINK, "Free website-hosting address", SV.LOW, ST.WEAK, 0.7,
                                 f"Anyone can create a site under {p.suffix} for free in minutes; official services use their own domains."))
    tld = p.suffix.rsplit(".", 1)[-1] if p.suffix else ""
    if tld in RISKY_TLDS and not (official or registry):
        issues.append(("warn", f"'.{tld}' is a top-level domain frequently abused for scams"))
        signals.append(URLSignal("risky_tld", C.SUSPICIOUS_LINK, f"Frequently abused ending (.{tld})", SV.LOW, ST.WEAK, 0.65,
                                 f"Cheap endings such as .{tld} are popular for throwaway scam sites (e.g. the fake e-challan domains reported in 2025-26 used .vip and .icu). Many honest sites use them too."))
    path_l = p.path.lower()
    ext = next((x for x in DANGEROUS_EXT if path_l.endswith(x)), None)
    if ext:
        issues.append(("fail", f"downloads a {DANGEROUS_EXT[ext]} file"))
        signals.append(URLSignal("dangerous_download", C.PHISHING, f"Downloads a {DANGEROUS_EXT[ext]}", SV.CRITICAL if ext == ".apk" else SV.HIGH, ST.STRONG, 0.92,
                                 "The link downloads an app or program directly. Fake 'RTO Challan' and banking APKs steal OTPs, SMS and card details.",
                                 "Don't install it. Use the official app from the Play Store."))
    elif any(path_l.endswith(x) for x in ARCHIVE_EXT):
        issues.append(("warn", "downloads a compressed archive"))
    if len(p.url) > 200:
        issues.append(("info", f"very long link ({len(p.url)} characters)"))
    status = "fail" if any(s == "fail" for s, _ in issues) else "warn" if any(s == "warn" for s, _ in issues) else "pass"
    checks.append(URLCheck(key="patterns", label="Suspicious URL patterns", status=status,
                           summary=issues[0][1].capitalize() if issues else "No suspicious patterns",
                           explanation="; ".join(t for _, t in issues) if issues else "Checked: IP address, '@' trick, port, subdomain depth, free hosting, risky endings, file downloads."))

    # ---- 6. shorteners and chat links
    host_core = p.host[4:] if p.host.startswith("www.") else p.host
    shortener = host_core in SHORTENERS
    chat = CHAT_LINKS.get(host_core)
    if shortener:
        checks.append(URLCheck(key="shortener", label="Link shortener", status="warn", summary=f"Shortened link ({host_core})",
                               explanation="Short links hide the real destination. TrustGuard resolves it in the backend when live checks are on."))
        signals.append(URLSignal("shortener", C.SUSPICIOUS_LINK, "Shortened link hides the destination", SV.MEDIUM, ST.WEAK, 0.75,
                                 "The real address is hidden behind a link shortener."))
    else:
        checks.append(URLCheck(key="shortener", label="Link shortener", status="pass", summary="Not a shortened link"))
    if chat:
        checks.append(URLCheck(key="chat", label="Chat link", status="info", summary=f"Opens a {chat}",
                               explanation="The link opens a conversation with an individual account instead of a website."))

    # ---- 7. query parameters
    personal, notes = _params(p)
    if notes:
        checks.append(URLCheck(key="parameters", label="Query parameters", status="warn", summary=notes[0], explanation="; ".join(notes),
                               details={"parameters": personal}))
        if personal:
            signals.append(URLSignal("tracking_params", C.PHISHING, "Personalised tracking link", SV.LOW, ST.WEAK, 0.7,
                                     "The link carries your personal details or a unique ID, so opening it can confirm to the sender that you received it."))
    else:
        checks.append(URLCheck(key="parameters", label="Query parameters", status="pass", summary="No personal data or redirects in the link"))

    return LexicalResult(checks, signals, personal, sorted(set(lookalike_of)), shortener, chat)


_EMAIL_RX = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.I)


def _params(p: ParsedURL) -> tuple[list[str], list[str]]:
    personal: list[str] = []
    notes: list[str] = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        val = v.strip()
        if not val:
            continue
        kind = None
        if _EMAIL_RX.fullmatch(val):
            kind = "an email address"
        elif re.fullmatch(r"(?:\+?91)?[6-9]\d{9}", re.sub(r"[\s-]", "", val)):
            kind = "a phone number"
        elif re.fullmatch(r"[A-Z]{2}\d{1,2}[A-Z]{0,3}\d{4}", val.upper().replace(" ", "")):
            kind = "a vehicle number"
        elif len(val) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", val):
            try:
                dec = base64.b64decode(val + "=" * (-len(val) % 4), altchars=b"-_").decode("utf-8", "ignore")
                if _EMAIL_RX.search(dec):
                    kind = "a base64-encoded email address"
            except (binascii.Error, ValueError):
                pass
            if kind is None and len(val) >= 24:
                kind = "a long unique identifier"
        if kind:
            personal.append(k)
            notes.append(f"parameter '{k}' carries {kind}")
        if re.match(r"(?i)https?://", val):
            other = urlsplit(val).hostname or ""
            if other and other != p.host:
                notes.append(f"parameter '{k}' redirects to another site ({other})")
    return personal, notes
