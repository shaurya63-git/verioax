"""Who a message claims to be from, and which domains really belong to them.

Used by both engines: the scam engine finds the *claimed* sender in the text; the URL engine checks whether a link
belongs to that sender, or merely imitates it.

Only domains we are confident about are listed. Two registry-level facts do most of the work for Indian institutions:
* ``.gov.in`` and ``.nic.in`` are issued only to government bodies by NIC;
* ``.bank.in`` is reserved for banks (RBI asked all banks to move there by 31 Oct 2025), ``.fin.in`` for other
  regulated financial entities.
A scammer cannot register under these suffixes, so a link there is strong evidence of authenticity, and a lookalike of
one (``parivahan-gov.in``, ``gov-in.top``) is strong evidence of impersonation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache

RESTRICTED_SUFFIXES: dict[str, str] = {
    "gov.in": "Government of India domain (registry restricted to government bodies)",
    "nic.in": "National Informatics Centre domain (government only)",
    "bank.in": "Indian bank domain (registry restricted to banks)",
    "fin.in": "Indian regulated financial-entity domain (restricted registry)",
    "mil.in": "Indian defence domain (restricted registry)",
    "ac.in": "Indian academic institution domain (restricted registry)",
    "edu.in": "Indian educational institution domain (restricted registry)",
    "res.in": "Indian research institution domain (restricted registry)",
}
GOVERNMENT_SUFFIXES = ("gov.in", "nic.in")


@dataclass(frozen=True)
class Entity:
    key: str
    name: str
    kind: str                       # government | bank | payments | telecom | courier | ecommerce | utility | media | platform
    aliases: tuple[str, ...]        # regex fragments that name the entity in a message
    domains: tuple[str, ...] = ()   # official domains (any subdomain of these is official)
    keywords: tuple[str, ...] = ()  # distinctive tokens for lookalike-domain detection
    fuzzy: bool = True              # allow near-miss (typo) matching on keywords
    verify: str = ""                # how to verify through an official channel

    @property
    def is_government(self) -> bool:
        return self.kind == "government"


ENTITIES: tuple[Entity, ...] = (
    # ------------------------------------------------------------------ government
    Entity("parivahan", "Parivahan / e-Challan", "government",
           (r"e-?\s?challan", r"traffic\s+(?:challan|police|fine|violation|department)", r"\bRTO\b", r"parivahan", r"\bvahan\b",
            r"sarathi", r"m-?parivahan", r"transport\s+department", r"\bMoRTH\b", r"चालान", r"परिवहन"),
           ("parivahan.gov.in", "morth.nic.in", "morth.gov.in"), ("parivahan", "echallan", "challan", "vahan", "sarathi", "morth"),
           verify="Check pending challans yourself at echallan.parivahan.gov.in or in the mParivahan app, using your vehicle number."),
    Entity("income_tax", "Income Tax Department", "government",
           (r"income\s*tax", r"\bITR\b", r"\bCBDT\b", r"tax\s+refund", r"आयकर"),
           ("incometax.gov.in",), ("incometax", "efiling", "itrefund"),
           verify="Log in at incometax.gov.in yourself. Refunds are credited automatically to your validated bank account."),
    Entity("uidai", "UIDAI (Aadhaar)", "government",
           (r"\bUIDAI\b", r"aadhaa?r\s+(?:centre|center|authority|department|seva)",),
           ("uidai.gov.in",), ("uidai", "maadhaar", "myaadhaar"),
           verify="Use the official myAadhaar portal at uidai.gov.in or call 1947."),
    Entity("epfo", "EPFO", "government",
           (r"\bEPFO?\b", r"provident\s+fund", r"\bPF\s+(?:account|withdrawal|balance|claim)"),
           ("epfindia.gov.in",), ("epfo", "epfindia"),
           verify="Check your PF account on epfindia.gov.in or the UMANG app."),
    Entity("india_post", "India Post", "government",
           (r"india\s*post", r"speed\s*post", r"post\s+office"),
           ("indiapost.gov.in",), ("indiapost", "speedpost"),
           verify="Track parcels on indiapost.gov.in. India Post does not ask for payment through SMS links."),
    Entity("law_enforcement", "Police / CBI / Customs / Courts", "government",
           (r"\bCBI\b", r"\bpolice\b", r"cyber\s*(?:cell|crime|police)", r"crime\s+branch", r"\bNCB\b", r"narcotics",
            r"enforcement\s+directorate", r"\bcustoms\b", r"\bcourt\b", r"\bjudge\b", r"\bTRAI\b", r"department\s+of\s+telecom", r"पुलिस"),
           ("cbi.gov.in", "cybercrime.gov.in", "trai.gov.in", "dot.gov.in", "sancharsaathi.gov.in"), ("cbi", "police", "cybercrime", "trai"),
           verify="Police, CBI and courts never demand money or 'digital arrest' over calls or messages. Call 1930 or visit your local police station."),
    Entity("rbi", "Reserve Bank of India", "government",
           (r"\bRBI\b", r"reserve\s+bank"), ("rbi.org.in",), ("rbi", "reservebank"),
           verify="RBI does not contact individuals about their accounts, prizes or funds. See rbi.org.in."),
    Entity("government_generic", "Government of India", "government",
           (r"govt\.?\s+of\s+india", r"government\s+of\s+india", r"\bministry\s+of\b", r"pradhan\s+mantri", r"\bPM[-\s]+(?:kisan|yojana|awas)",
            r"सरकार", r"भारत\s+सरकार"),
           (), ("govin", "gov-in", "gov"), fuzzy=False,
           verify="Government schemes and notices are published on official .gov.in websites and by PIB."),
    # ------------------------------------------------------------------ banks
    Entity("sbi", "State Bank of India", "bank", (r"\bSBI\b", r"state\s+bank\s+of\s+india", r"\bYONO\b"),
           ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "sbilife.co.in", "sbimf.com", "sbigeneral.in"), ("sbi", "onlinesbi", "yonosbi", "yono"),
           verify="Use the YONO app or onlinesbi.sbi typed in yourself, or call the number on your card."),
    Entity("hdfc", "HDFC Bank", "bank", (r"\bHDFC\b",), ("hdfcbank.com", "hdfc.bank.in", "hdfcbank.bank.in", "hdfclife.com", "hdfcergo.com", "hdfcsec.com", "hdfcfund.com"), ("hdfcbank", "hdfc"),
           verify="Use the HDFC Bank app or call the number on your card."),
    Entity("icici", "ICICI Bank", "bank", (r"\bICICI\b",), ("icicibank.com", "icici.bank.in", "icicidirect.com", "iciciprulife.com", "icicilombard.com", "icicipruamc.com"), ("icicibank", "icici"),
           verify="Use the iMobile app or call the number on your card."),
    Entity("axis", "Axis Bank", "bank", (r"axis\s+bank",), ("axisbank.com", "axis.bank.in", "axismf.com", "axisdirect.in"), ("axisbank",),
           verify="Use the Axis Mobile app or call the number on your card."),
    Entity("kotak", "Kotak Mahindra Bank", "bank", (r"\bkotak\b",), ("kotak.com", "kotak.bank.in", "kotaksecurities.com", "kotaklife.com"), ("kotak", "kotakbank"),
           verify="Use the Kotak app or call the number on your card."),
    Entity("pnb", "Punjab National Bank", "bank", (r"\bPNB\b", r"punjab\s+national\s+bank"), ("pnbindia.in", "pnb.bank.in"), ("pnbindia", "pnb"),
           verify="Use PNB ONE or call the number on your card."),
    Entity("bob", "Bank of Baroda", "bank", (r"bank\s+of\s+baroda", r"\bBOB\b"), ("bankofbaroda.in", "bankofbaroda.bank.in"), ("bankofbaroda", "baroda"),
           verify="Use bob World or call the number on your card."),
    Entity("canara", "Canara Bank", "bank", (r"canara\s+bank",), ("canarabank.com", "canarabank.bank.in"), ("canarabank",),
           verify="Use the Canara ai1 app or call the number on your card."),
    Entity("union_bank", "Union Bank of India", "bank", (r"union\s+bank",), ("unionbankofindia.co.in", "unionbank.bank.in"), ("unionbank",),
           verify="Use the Union Bank app or call the number on your card."),
    # ------------------------------------------------------------------ payments
    Entity("paytm", "Paytm", "payments", (r"\bpaytm\b",), ("paytm.com", "paytm.in", "paytmbank.com"), ("paytm",), fuzzy=False),
    Entity("phonepe", "PhonePe", "payments", (r"phone\s?pe",), ("phonepe.com",), ("phonepe",)),
    Entity("gpay", "Google Pay", "payments", (r"google\s+pay", r"\bgpay\b"), ("google.com", "gpay.app.goo.gl"), ("googlepay", "gpay"), fuzzy=False),
    Entity("npci", "NPCI / BHIM UPI", "payments", (r"\bNPCI\b", r"\bBHIM\b"), ("npci.org.in", "bhimupi.org.in"), ("npci", "bhimupi")),
    # ------------------------------------------------------------------ telecom / utilities
    Entity("jio", "Jio", "telecom", (r"\bjio\b",), ("jio.com",), ("jio",), fuzzy=False),
    Entity("airtel", "Airtel", "telecom", (r"\bairtel\b",), ("airtel.in", "airtel.com"), ("airtel",)),
    Entity("vi", "Vi (Vodafone Idea)", "telecom", (r"vodafone", r"\bvi\s+(?:customer|user|sim)"), ("myvi.in",), ("myvi", "vodafone")),
    Entity("bsnl", "BSNL", "telecom", (r"\bBSNL\b",), ("bsnl.co.in",), ("bsnl",)),
    Entity("electricity", "Electricity distribution company", "utility",
           (r"electricity\s+(?:board|department|office|bill|connection)", r"\bbijli\b", r"power\s+(?:cut|bill|supply)", r"\bBESCOM\b",
            r"\bMSEDCL\b", r"\bMSEB\b", r"\bTNEB\b", r"\bTANGEDCO\b", r"\bBSES\b", r"\bUPPCL\b", r"\bKSEB\b", r"बिजली"),
           (), ("electricity", "bijli"), fuzzy=False,
           verify="Check your bill in your electricity board's official app or website. Boards don't ask you to call a personal number."),
    Entity("lpg", "LPG gas provider", "utility", (r"\bindane\b", r"\bHP\s+gas\b", r"bharat\s*gas"),
           ("iocl.com", "indane.co.in", "myhpgas.in", "hindustanpetroleum.com", "ebharatgas.com", "bharatpetroleum.in"), ("indane", "hpgas", "bharatgas")),
    # ------------------------------------------------------------------ couriers / e-commerce / platforms
    Entity("dtdc", "DTDC", "courier", (r"\bDTDC\b",), ("dtdc.in", "dtdc.com"), ("dtdc",)),
    Entity("delhivery", "Delhivery", "courier", (r"delhivery",), ("delhivery.com",), ("delhivery",), fuzzy=False),
    Entity("bluedart", "Blue Dart", "courier", (r"blue\s?dart",), ("bluedart.com",), ("bluedart",)),
    Entity("fedex", "FedEx", "courier", (r"\bfedex\b",), ("fedex.com",), ("fedex",)),
    Entity("dhl", "DHL", "courier", (r"\bDHL\b",), ("dhl.com", "dhl.co.in"), ("dhl",), fuzzy=False),
    Entity("amazon", "Amazon", "ecommerce", (r"\bamazon\b",), ("amazon.in", "amazon.com"), ("amazon",)),
    Entity("flipkart", "Flipkart", "ecommerce", (r"flipkart",), ("flipkart.com",), ("flipkart",)),
    Entity("irctc", "IRCTC", "ecommerce", (r"\bIRCTC\b",), ("irctc.co.in",), ("irctc",)),
    Entity("lic", "LIC", "ecommerce", (r"\bLIC\b", r"life\s+insurance\s+corporation"), ("licindia.in",), ("licindia",)),
    Entity("whatsapp", "WhatsApp", "platform", (r"whats\s?app",), ("whatsapp.com", "whatsapp.net", "wa.me"), ("whatsapp",)),
    Entity("kbc", "KBC (Kaun Banega Crorepati)", "media", (r"\bKBC\b", r"kaun\s+banega\s+crorepati"), ("sonyliv.com", "setindia.com"), ("kbc",), fuzzy=False,
           verify="There is no 'KBC lottery'. The show never picks winners by SMS or WhatsApp."),
)

ENTITY_BY_KEY = {e.key: e for e in ENTITIES}


@cache
def _alias_rx(entity_key: str) -> re.Pattern:
    e = ENTITY_BY_KEY[entity_key]
    parts = []
    for a in e.aliases:
        # short ALL-CAPS acronyms are matched case-sensitively ("ED", "RBI" - not "red" or "rbi" inside words)
        is_acronym = re.fullmatch(r"\\b[A-Z]{2,5}\\b", a) is not None
        parts.append(a if is_acronym else f"(?i:{a})")
    return re.compile("|".join(parts))


def find_entities(text: str) -> list[tuple[Entity, int, int]]:
    """All (entity, start, end) mentions in the text."""
    out = []
    for e in ENTITIES:
        for m in _alias_rx(e.key).finditer(text):
            out.append((e, m.start(), m.end()))
    out.sort(key=lambda x: x[1])
    return out


def restricted_suffix(host: str) -> str | None:
    host = host.lower().rstrip(".")
    for suf in RESTRICTED_SUFFIXES:
        if host == suf or host.endswith("." + suf):
            return suf
    return None


def official_entity_for(host: str) -> Entity | None:
    host = host.lower().rstrip(".")
    if host.endswith(".sbi") or host == "sbi":
        return ENTITY_BY_KEY["sbi"]                     # .sbi is State Bank of India's own top-level domain
    for e in ENTITIES:
        for d in e.domains:
            if host == d or host.endswith("." + d):
                return e
    return None


def host_is_official_for(host: str, entity: Entity) -> bool:
    """True when `host` legitimately belongs to the claimed entity (its own domain or its sector's restricted registry)."""
    owner = official_entity_for(host)
    if owner is not None and owner.key == entity.key:
        return True
    suf = restricted_suffix(host)
    if entity.is_government and suf in GOVERNMENT_SUFFIXES:
        return True
    if entity.kind == "bank" and suf == "bank.in":
        return True
    return False
