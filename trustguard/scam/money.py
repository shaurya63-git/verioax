"""Money amounts in messages: "$5,600", "Rs 25,00,000", "₹10k", "0.05 BTC", "1,000 USDT", "25 lakh", "$4.200".

Used to tell an everyday offer ("₹100 off", "₹50 cashback") from an unrealistic one ("$5,600 to everyone who
registers"). The rupee equivalents below are deliberately rough, fixed, order-of-magnitude rates: they decide only
whether a reward is *large*, never anything shown to the user as a price or a conversion.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# rough rupee value of one unit - thresholds only (see module docstring)
INR_RATE = {"inr": 1.0, "usd": 85.0, "usdt": 85.0, "usdc": 85.0, "eur": 92.0, "gbp": 108.0, "btc": 5_000_000.0, "eth": 200_000.0,
            "bnb": 40_000.0, "sol": 12_000.0, "trx": 10.0, "doge": 10.0, "xrp": 40.0, "matic": 40.0, "ton": 400.0, "crypto": 85.0}
LARGE_REWARD_INR = 5_000          # a "free" reward above this, for doing nothing, is not something genuine companies give away
VERY_LARGE_REWARD_INR = 50_000

_PRE = {"₹": "inr", "rs": "inr", "rs.": "inr", "inr": "inr", "$": "usd", "us$": "usd", "usd": "usd", "€": "eur", "eur": "eur", "£": "gbp",
        "gbp": "gbp", "usdt": "usdt", "usdc": "usdc"}
_POST = {"rupees": "inr", "rupee": "inr", "rs": "inr", "inr": "inr", "₹": "inr", "dollars": "usd", "dollar": "usd", "usd": "usd", "$": "usd",
         "bucks": "usd", "euros": "eur", "euro": "eur", "€": "eur", "pounds": "gbp", "£": "gbp", "usdt": "usdt", "usdc": "usdc", "btc": "btc",
         "bitcoin": "btc", "bitcoins": "btc", "eth": "eth", "ether": "eth", "ethereum": "eth", "bnb": "bnb", "sol": "sol", "trx": "trx",
         "doge": "doge", "xrp": "xrp", "matic": "matic", "ton": "ton", "rupaye": "inr", "rupaiye": "inr", "rupay": "inr", "रुपये": "inr", "रुपए": "inr", "रु": "inr", "डॉलर": "usd"}
_MULT = {"k": 1e3, "thousand": 1e3, "lakh": 1e5, "lakhs": 1e5, "lac": 1e5, "lacs": 1e5, "crore": 1e7, "crores": 1e7, "cr": 1e7,
         "million": 1e6, "mn": 1e6, "m": 1e6, "लाख": 1e5, "करोड़": 1e7, "करोड": 1e7}

NUM = r"\d{1,3}(?:[,.]\d{2,3})+(?:\.\d{1,2})?|\d+(?:\.\d+)?"
MULT = r"(?:k|thousand|lakhs?|lacs?|crores?|cr|million|mn|लाख|करोड़?)"
_PRE_RX = r"(?:₹|rs\.?|inr|us\$|usd|\$|€|eur|£|gbp|usdt|usdc)"
_POST_RX = (r"(?:rupees?|rupa(?:i)?ye|rupay|rs\.?|inr|₹|dollars?|usd|bucks|euros?|€|pounds|£|usdt|usdc|btc|bitcoins?|eth|ether(?:eum)?|bnb|sol|trx|doge|xrp|"
            r"matic|ton|रुपये|रुपए|रु|डॉलर)")
# One amount, usable inside other patterns (no capture groups).
AMOUNT = (rf"(?:{_PRE_RX}\s?(?:{NUM})(?:\s?{MULT}(?![a-z]))?(?:/-)?|(?:{NUM})\s?(?:{MULT}\s?)?{_POST_RX}(?![a-z])|"
          rf"(?:{NUM})\s?(?:lakhs?|lacs?|crores?|लाख|करोड़?)(?![a-z]))")
_FULL = re.compile(rf"(?i)(?P<pre>{_PRE_RX})?\s?(?P<num>{NUM})\s?(?P<mult>{MULT}(?![a-z]))?\s?(?P<post>{_POST_RX}(?![a-z]))?")
AMOUNT_RX = re.compile(rf"(?i)(?<![\w.]){AMOUNT}")


@dataclass(frozen=True)
class Amount:
    start: int
    end: int
    raw: str
    value: float
    currency: str

    @property
    def inr(self) -> float:
        return self.value * INR_RATE.get(self.currency, 85.0)


def _number(num: str, currency: str) -> float:
    s = num
    if re.fullmatch(r"\d{1,3}\.\d{3}", s) and currency in ("usd", "eur", "gbp"):
        s = s.replace(".", "")                           # "$4.200": a thousands separator, not a decimal point
    elif re.fullmatch(r"\d{1,3}(?:\.\d{3})+", s):
        s = s.replace(".", "")
    s = s.replace(",", "")
    try:
        return float(s)
    except ValueError:
        return 0.0


def parse(raw: str) -> tuple[float, str] | None:
    m = _FULL.search(raw)
    if not m:
        return None
    pre = (m.group("pre") or "").lower()
    post = (m.group("post") or "").lower()
    mult = (m.group("mult") or "").lower()
    currency = _PRE.get(pre) or _POST.get(post) or ("inr" if mult in ("lakh", "lakhs", "lac", "lacs", "crore", "crores", "लाख", "करोड़", "करोड") else "")
    if not currency:
        return None
    value = _number(m.group("num"), currency) * _MULT.get(mult, 1.0)
    return value, currency


def find_amounts(text: str) -> list[Amount]:
    out: list[Amount] = []
    for m in AMOUNT_RX.finditer(text):
        raw = m.group().strip()
        p = parse(raw)
        if p and p[0] > 0:
            out.append(Amount(m.start(), m.start() + len(m.group().rstrip()), raw, p[0], p[1]))
    return out
