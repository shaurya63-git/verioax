"""Message-level scam and hoax indicators.

Each indicator is a small, explainable rule: the phrases it looks for (English, Hinglish and some Hindi), the category
it supports, how severe it is, and - importantly - how much it proves on its own (``Strength``):

* WEAK   - common in scams but also in honest messages (urgency, "Dear customer", "click the link");
* STRONG - something legitimate senders practically never do (asking for an OTP, a fee to release a prize);
* CONFIRMED is never produced from wording alone; it needs verifiable evidence (threat intelligence, a page that asks
  for a CVV on an impersonating domain).

Weak indicators alone can never push a message above MEDIUM risk (see ``trustguard.risk``), which is what stops every
urgent office message from being called a scam.

Context indicators (severity INFO: "mentions cryptocurrency", "mentions a casino", "uses a promo code") add no points
at all. A crypto, casino or promo-code mention is not evidence of fraud; such indicators exist so that the combination
rules in ``trustguard.scam.analyzer`` can recognise a complete attack pattern (a large, instantly withdrawable bonus for
registering on an outside site, with a countdown) while every single ingredient stays harmless on its own.

Matching runs twice: on the text as written and on an evasion-resistant copy (``trustguard.scam.normalize``: spaced-out
letters, "withdr@w", invisible characters, look-alike letters). The copy can only add matches.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..schemas import ScamCategory as C
from ..schemas import Severity as SV
from ..schemas import Strength as ST
from .money import AMOUNT
from .normalize import normalize


@dataclass(frozen=True)
class Indicator:
    key: str
    category: C
    title: str
    severity: SV
    strength: ST
    confidence: float
    patterns: tuple[str, ...]
    explanation: str
    action: str
    negate_before: str | None = None      # regex; if found just before the match, the match is ignored
    negate_after: str | None = None       # regex; if found just after the match, the match is ignored
    skip_if_near: str | None = None       # regex; if found within 40 chars on either side, ignore
    max_hits: int = 3

    def compiled(self) -> list[re.Pattern]:
        return _compile(self.patterns)


_CACHE: dict[tuple[str, ...], list[re.Pattern]] = {}


def _compile(patterns: tuple[str, ...]) -> list[re.Pattern]:
    if patterns not in _CACHE:
        _CACHE[patterns] = [re.compile(p, re.I) for p in patterns]
    return _CACHE[patterns]


SECRET = (r"(?:otp|one[\s-]?time\s+pass(?:word|code)|verification\s+code|security\s+code|login\s+code|(?:6|six|4|four)[\s-]?digit\s+code|"
          r"(?:the\s+)?code\s+(?:you|we)\s+(?:just\s+)?(?:received|got|sent)|upi\s*pin|m-?pin|atm\s*pin|\bpin\b|cvv|"
          r"card\s+(?:number|details|no)|expiry(?:\s+date)?|net\s?banking\s+(?:password|details|credentials|id)|login\s+(?:details|credentials|id|password)|"
          r"password|user\s?id)")
# Secrets that a genuine message would never ask you to type in from an SMS (an OTP is different: genuine OTP messages
# do say "enter this OTP on the website").
BANKING_SECRET = (r"(?:upi\s*pin|m-?pin|atm\s*pin|cvv|card\s+(?:number|details|no)|expiry(?:\s+date)?|"
                  r"net\s?banking\s+(?:password|details|credentials|id)|login\s+(?:details|credentials|password))")
ASK = (r"(?:share|send|tell|provide|give|forward|reply\s+with|"
       r"bata(?:o|yein|ye|na|iye)?|bhej(?:o|ein|e|na|iye)?|de\s?do|dijiye|likh\s+kar\s+bhej\w*)")
ENTER = r"(?:enter|submit|confirm|verify|update|fill(?:\s+in)?|type\s+in|daalo|daalein|darj\s+karein)"
NEGATION_BEFORE = r"\b(?:do\s+not|don'?t|never|not\s+to|no\s+one\s+will|will\s+never|won'?t|kabhi\s+bhi|kabhi|mat|na)\s+(?:\w+\s+){0,3}$"
NEGATION_AFTER = r"^\s*(?:\w+\s+){0,3}(?:na|nahi|nahin|mat)\b"


def _a(pattern: str) -> str:
    """Insert the money-amount pattern ("$5,600", "Rs 25,00,000", "0.05 BTC") where a pattern says {AMOUNT}."""
    return pattern.replace("{AMOUNT}", AMOUNT)


CRYPTO_TICKER = r"(?:btc|bitcoins?|eth|ether(?:eum)?|usdt|usdc|bnb|sol|solana|trx|doge|dogecoin|xrp|matic|ton|crypto)"

INDICATORS: tuple[Indicator, ...] = (
    # ------------------------------------------------------------------ pressure
    Indicator("urgency", C.SOCIAL_ENGINEERING, "Urgency / pressure tactic", SV.LOW, ST.WEAK, 0.75,
              (r"\b(?:urgent(?:ly)?|immediately|right\s+away|act\s+now|hurry|asap|without\s+delay|at\s+the\s+earliest)\b",
               r"\b(?:within|in\s+the\s+next|in)\s+(?:\d{1,2}|twenty[\s-]four|forty[\s-]eight|two|few)\s*(?:hours?|hrs?|minutes?|mins?)\b",
               r"\b(?:last\s+(?:date|day|chance|reminder|warning)|final\s+(?:notice|reminder|warning|chance))\b",
               r"\bexpir(?:es|ing|y)\s+(?:today|tonight|soon|in\s+\d+)\b", r"\b(?:before|by)\s+(?:midnight|tonight|end\s+of\s+(?:the\s+)?day)\b",
               r"\b(?:turant|turrant|abhi|jaldi|aaj\s+hi|fauran|jald\s+se\s+jald)\b", r"(?:तुरंत|अभी|जल्दी|आज\s+ही)",
               r"\b(?:only\s+)?\d{1,2}\s+(?:hours?|hrs?|minutes?|mins?)\s+(?:left|remaining)\b", r"\bdon'?t\s+miss\s+(?:out|your\s+chance|this\s+chance)\b",
               r"\b(?:buy|join|invest|register|act)\s+(?:now\s+)?before\s+(?:it'?s\s+too\s+late|it\s+(?:moons?|pumps?|ends|closes|explodes)|the\s+(?:price|presale|offer))\b"),
              "Pressure to act quickly is a common way to stop people from checking. On its own it is normal in many genuine messages.",
              "Take your time. Verify through the official app or website before doing anything."),
    Indicator("threat_of_consequence", C.SOCIAL_ENGINEERING, "Threat of penalty, blocking or legal action", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\b(?:will|shall|may|would)\s+be\s+(?:permanently\s+)?(?:blocked|suspended|deactivated|disconnected|cancell?ed|frozen|terminated|seized|blacklisted|closed|barred)\b",
               r"\b(?:licen[cs]e|account|sim|number|connection|card|pan|kyc|vehicle\s+registration)\s+(?:is\s+being|has\s+been|will\s+be)\s+(?:blocked|suspended|deactivated|cancell?ed|seized)\b",
               r"\b(?:legal\s+(?:action|proceedings|notice)|court\s+(?:summons|proceedings|case|notice|hearing)|arrest(?:ed)?|arrest\s+warrant|\bFIR\b|"
               r"police\s+(?:case|complaint|action)|penalty\s+will\s+(?:increase|double)|additional\s+(?:charges|penalty|fine)|recovery\s+(?:action|proceedings))",
               r"\b(?:band|block)\s+(?:ho\s+jayega|ho\s+jaega|kar\s+diya\s+jayega|kiya\s+jayega)\b", r"\b(?:warna|nahi\s+to)\b",
               r"(?:बंद\s+(?:हो\s+जाएगा|कर\s+दिया\s+जाएगा)|कानूनी\s+कार्रवाई)"),
              "Threatening fines, blocking, arrest or court action is a pressure tactic. Real departments send formal notices and give time to respond through official channels.",
              "Don't react to the threat. Look the matter up yourself on the official website or app."),
    Indicator("secrecy", C.SOCIAL_ENGINEERING, "Asks you to keep it secret", SV.MEDIUM, ST.STRONG, 0.85,
              (r"\b(?:do\s+not|don'?t|dont)\s+(?:tell|inform|share\s+this\s+with|disclose\s+(?:this\s+)?to)\s+(?:anyone|anybody|your\s+family|family\s+members|your\s+bank|the\s+police)\b",
               r"\bkeep\s+(?:this|it)\s+(?:confidential|secret|private)\b", r"\bkisi\s+ko\s+(?:mat|na)\s+(?:batana|batayein|bataye|batao)\b"),
              "Telling you not to inform family, your bank or the police isolates you from people who would recognise the scam.",
              "Talk to someone you trust and contact the organisation through its official number."),
    Indicator("generic_greeting", C.SOCIAL_ENGINEERING, "Generic greeting", SV.LOW, ST.WEAK, 0.6,
              (r"\bdear\s+(?:customer|user|sir|madam|member|valued\s+customer|account\s+holder|vehicle\s+owner|card\s?holder|citizen|applicant|subscriber)\b",),
              "Mass messages often use a generic greeting. Many genuine bulk messages do too, so this is a minor signal.",
              "", max_hits=1),
    # ------------------------------------------------------------------ money
    Indicator("payment_request", C.URGENT_PAYMENT, "Asks you to pay", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\bpay\s+(?:now|immediately|today|online|the\s+(?:fine|amount|penalty|dues|bill|fee|charges|challan)|your\s+(?:fine|challan|dues|bill)|(?:rs\.?|inr|₹))",
               r"\b(?:pending|unpaid|outstanding|overdue)\s+(?:e-?\s?challan|challan|fine|amount|dues|bill|payment|penalty|fee)s?\b",
               r"\b(?:make|complete|clear)\s+(?:the\s+|your\s+)?(?:payment|dues)\b", r"\bpayment\s+(?:is\s+)?(?:pending|due|failed|required|overdue)\b",
               r"\b(?:transfer|send|deposit)\s+(?:rs\.?|inr|₹|money|the\s+amount|funds|payment)\b", r"\bscan\s+(?:the\s+|this\s+)?qr\b",
               r"\b(?:payment|bhugtan|bhugtaan)\s+(?:karein|karo|kare|kijiye|kar\s+dein)\b", r"\bpaise\s+(?:bhejo|bhejein|transfer)\b", r"भुगतान\s+करें"),
              "The message asks you to pay. Combined with a link or an unofficial sender this is the core of most payment scams.",
              "Pay only through the official website or app that you open yourself - never through a link in a message.",
              negate_before=NEGATION_BEFORE),
    Indicator("fee_request", C.FINANCIAL_FRAUD, "Fee demanded to release money, a prize, a parcel or a job", SV.HIGH, ST.STRONG, 0.82,
              (r"\b(?:processing|registration|activation|verification|clearance|delivery|customs|handling|security|refundable|joining|documentation|"
               r"insurance|gst|tds|release|courier|transfer|unlock|unfreeze|kyc|network|gas|withdrawal|file|renewal|re-?delivery|conversion|"
               r"upgrade)\s+(?:fee|fees|charge|charges|deposit|amount)\b",
               r"\b(?:advance|upfront)\s+(?:payment|fee|amount)\b",
               r"\b(?:pay|deposit|send|transfer)\b[^.\n]{0,40}\bto\s+(?:claim|receive|release|unlock|activate|withdraw|get\s+your|confirm\s+your\s+(?:seat|slot|job))\b",
               r"\b(?:security\s+deposit|joining\s+fee|registration\s+fee|processing\s+fee)\b[^.\n]{0,25}\b(?:bhejo|bhejein|bhejiye|jama\s+kar\w*|dijiye|do)\b"),
              "Being asked to pay a fee to receive money, a prize, a parcel or a job is the signature of advance-fee fraud.",
              "Don't pay. Real prizes, refunds and jobs never require an upfront fee.",
              negate_before=NEGATION_BEFORE,
              # "delivery charges of Rs 40 apply on orders below Rs 499" is an ordinary shop notice, not a demand
              skip_if_near=r"\b(?:will\s+)?appl(?:y|ies|icable)\b|\bon\s+orders?\s+(?:below|under|above|of)\b|\bfree\s+delivery\b"),
    Indicator("upi_collect_trick", C.FINANCIAL_FRAUD, "Asks for your UPI PIN to 'receive' money", SV.CRITICAL, ST.STRONG, 0.9,
              (r"\b(?:to\s+(?:receive|get|claim|credit)|for\s+(?:receiving|refund|cashback|credit))\b[^.\n]{0,60}\b(?:enter|scan|approve|accept|put|use)\b[^.\n]{0,25}\b(?:upi\s+)?(?:pin|qr)\b",
               r"\b(?:enter|approve)\b[^.\n]{0,30}\bpin\b[^.\n]{0,40}\b(?:receive|refund|cashback|credited|credit)\b",
               r"\b(?:accept|approve)\s+(?:the|my|this|that)\s+(?:payment\s+|collect\s+|upi\s+)?request\b[^.\n]{0,60}\b(?:return|refund|receive|get\s+(?:it|the\s+money)|send\s+it\s+back)\b",
               r"\b(?:approve|accept)\s+(?:karke|kar\s+ke|karein|karo)\b[^.\n]{0,30}\bpin\b"),
              "You never need to enter your UPI PIN or scan a QR code to receive money. Entering the PIN sends money out of your account.",
              "Decline the request. Only enter your UPI PIN when you are the one paying."),
    Indicator("credential_request", C.OTP_SCAM, "Asks for an OTP, PIN, CVV or password", SV.CRITICAL, ST.STRONG, 0.88,
              (rf"\b{ASK}\b[^.\n]{{0,30}}\b{SECRET}", rf"\b{SECRET}\b[^.\n]{{0,25}}\b(?:share|send|bata(?:o|yein|ye)?|bhej(?:o|ein|e)?|batana|bhejna)\b",
               r"\b(?:tell|share|send|read\s+out|forward|give)\s+(?:me|us)\s+(?:the|that|this)\s+(?:\d[\s-]?digit\s+)?code\b"),
              "The message asks for an OTP, PIN, CVV or password. Banks, government offices and delivery companies never ask for these.",
              "Never share OTPs, PINs, CVV or passwords with anyone - not even someone who says they are from your bank.",
              negate_before=NEGATION_BEFORE, negate_after=NEGATION_AFTER,
              # food/parcel delivery OTPs are legitimately shown to the delivery partner at your door
              skip_if_near=r"delivery\s+(?:partner|agent|executive|boy|person)|at\s+the\s+time\s+of\s+delivery|while\s+receiving\s+(?:the\s+)?(?:order|parcel)"),
    Indicator("credential_entry", C.PHISHING, "Asks you to enter card or banking details", SV.HIGH, ST.WEAK, 0.75,
              (rf"\b{ENTER}\b[^.\n]{{0,30}}\b{BANKING_SECRET}",),
              "The message asks you to type in card or banking details. Do that only inside your bank's own app or website, never on a page opened from a message.",
              "Open your bank's app yourself instead of following the message.",
              negate_before=NEGATION_BEFORE, negate_after=NEGATION_AFTER),
    Indicator("money_amount", C.FINANCIAL_FRAUD, "Mentions an amount of money", SV.INFO, ST.WEAK, 0.9,
              (r"(?:₹|\brs\.?|\binr)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:lakh|lac|crore|k))?\b",),
              "Context only: the amount is shown so you can compare it with what official records say.", "", max_hits=2),
    # ------------------------------------------------------------------ account / identity lures
    Indicator("kyc_suspension", C.PHISHING, "KYC / account suspension warning", SV.MEDIUM, ST.WEAK, 0.8,
              (r"\bkyc\b[^.\n]{0,40}\b(?:expired|expir(?:es|ing)|pending|incomplete|not\s+updated|update|suspended|blocked|verification)\b",
               r"\b(?:incomplete|pending|expired|outdated|failed|incorrect)\s+(?:e-?)?kyc\b",
               r"\b(?:update|complete|verify|re-?verify)\s+(?:your\s+)?(?:kyc|pan|aadhaa?r|account\s+details|bank\s+details)\b",
               r"\b(?:pan|aadhaa?r)\b[^.\n]{0,25}\b(?:not\s+linked|link(?:ed)?\s+(?:now|immediately|today))\b",
               r"\b(?:account|card|yono|net\s?banking|wallet)\b[^.\n]{0,30}\b(?:blocked|suspended|frozen|deactivated|on\s+hold|locked)\b",
               r"\b(?:account|card|kyc|wallet|profile)\b[^.\n]{0,20}\b(?:needs?|requires?|is\s+pending)\s+(?:urgent\s+)?(?:verification|re-?verification|update|re-?kyc)\b"),
              "Warnings that your KYC has expired or your account will be blocked are the most common banking phishing lure. Banks ask you to use their own app or visit a branch.",
              "Open your bank's app yourself, or call the number printed on your card."),
    Indicator("apk_install", C.PHISHING, "Asks you to install an app from a file or link", SV.HIGH, ST.STRONG, 0.85,
              (r"\.apk\b", r"\b(?:download|install)\s+(?:this|the|our|attached|below|given)?\s*(?:app|application|apk|file)\b",
               r"(?:एपीके|\bAPK\s+(?:file|फाइल))"),
              "Apps sent as files or links (.apk) bypass Play Store checks. Fake 'RTO Challan' and 'bank' apps read your SMS, OTPs and card details.",
              "Don't install apps from messages. Get official apps from the Play Store only.",
              skip_if_near=r"play\s?store|app\s?store|google\s+play"),
    Indicator("remote_access", C.SOCIAL_ENGINEERING, "Asks you to install remote-access / screen-sharing app", SV.CRITICAL, ST.STRONG, 0.9,
              (r"\b(?:anydesk|any\s+desk|teamviewer|team\s+viewer|quick\s?support|rustdesk|airdroid|ammyy|ultraviewer)\b",
               r"\bscreen\s?(?:share|sharing)\b", r"\b(?:install|download)\b[^.\n]{0,30}\b(?:remote|support)\s+app\b"),
              "Remote-access apps let a stranger see and control your phone, including your banking apps and OTPs.",
              "Don't install screen-sharing or remote-access apps at anyone's request."),
    Indicator("callback_number", C.SOCIAL_ENGINEERING, "Asks you to call or message a personal number", SV.LOW, ST.WEAK, 0.7,
              # (?<!\d): a toll-free "1800-208-9100" is not a mobile number starting at its second digit
              (r"\b(?:call|contact|whatsapp|reach|dial|message|sampark\s+karein|call\s+karein)\b[^.\n]{0,25}(?<![\d-])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b",
               r"\b(?:call|contact|whatsapp|dial)\b[^.\n]{0,25}(?<![\d-])(?:\+?91[\s-]?)?[6-9]\d{2}[\s-]?\d{3}[\s-]?\d{4}\b"),
              "You're asked to call or message a mobile number. Organisations use published helpline numbers, not personal mobiles.",
              "Use only the helpline number on the organisation's official website, card or bill."),
    Indicator("click_link_cta", C.PHISHING, "Tells you to click a link", SV.LOW, ST.WEAK, 0.7,
              (r"\b(?:click|tap|open|visit|go\s+to|follow)\b[^.\n]{0,20}\b(?:the\s+|this\s+|below\s+)?(?:link|url|website|here)\b",
               r"\blink\s+(?:par|pe)\s+(?:click|tap)\s+(?:karein|karo|kare)\b", r"लिंक\s+पर\s+क्लिक"),
              "Messages that push you to a link want you on a page they control.", "Type the official address yourself instead of tapping the link.",
              max_hits=1),
    # ------------------------------------------------------------------ lures
    Indicator("prize_claim", C.LOTTERY_PRIZE, "Prize, lottery or reward claim", SV.MEDIUM, ST.STRONG, 0.8,
              (r"\b(?:lucky\s+winner|prize\s+money|winning\s+amount)\b",
               r"\byou\s+(?:have\s+)?(?:won|been\s+selected\s+for\s+(?:a\s+)?(?:prize|reward|gift)|are\s+(?:the\s+)?(?:lucky\s+)?winner)\b",
               r"\bclaim\s+(?:your\s+)?(?:prize|reward|gift|cashback|winnings|lottery)\b", r"\bfree\s+(?:iphone|laptop|mobile|scooty|bike|car|tv|smartphone)\b",
               r"\b(?:aapne|apne)\b[^.\n]{0,25}\b(?:jeeta|jeete|jeet\s+liya|jeeti)\b", r"\binaam\b", r"(?:लॉटरी|इनाम|आपने\s.{0,25}जीत)",
               r"\byour\s+(?:mobile\s+|whatsapp\s+|phone\s+|sim\s+)?(?:number|sim(?:\s+card)?|email(?:\s+(?:id|address))?)\s+(?:has\s+)?(?:won|been\s+(?:selected|chosen))\b",
               r"\b(?:winner|won)\b[^.\n]{0,40}\b(?:lottery|lucky\s+draw|sweepstakes?|promotion\s+20\d\d|bumper\s+draw)\b"),
              "Unexpected prizes, lotteries and rewards you never entered are a classic lure; the 'prize' is used to extract a fee or your details.",
              "Ignore it. You can't win a lottery you never entered."),
    # the bare words: lottery results, a casino jackpot or a shop's lucky draw are ordinary news - only a claim that YOU won is a prize claim
    Indicator("lottery_mention", C.LOTTERY_PRIZE, "Mentions a lottery or lucky draw", SV.LOW, ST.WEAK, 0.6,
              (r"\b(?:lucky\s+draw|lottery|jackpot|bumper\s+(?:prize|draw)|grand\s+prize|mega\s+prize)\b",),
              "A lottery or lucky draw is mentioned. On its own that is ordinary; it matters when the message also says you won something you "
              "never entered, or asks for a fee or a call.", "", max_hits=1),
    Indicator("congratulations", C.LOTTERY_PRIZE, "Congratulatory opener", SV.LOW, ST.WEAK, 0.6,
              (r"\b(?:congratulations|congrats)\b", r"बधाई\s+हो"), "Often used to open prize scams, but also common in honest messages.", "", max_hits=1),
    Indicator("job_lure", C.FAKE_JOB, "Easy-money job offer", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\b(?:work\s+from\s+home|part[\s-]?time\s+(?:job|work|income)|home[\s-]based\s+(?:job|work))\b",
               r"\bearn\s+(?:up\s+to\s+)?(?:rs\.?|₹|inr)?\s?\d[\d,]*\s*(?:per|a|/)\s*(?:day|hour|week)\b", r"\bdaily\s+(?:income|earning|payment|salary|payout)\b",
               r"\b(?:like|subscribe|rate|review)\b[^.\n]{0,20}\b(?:videos?|youtube|hotels?|products?|posts?)\b[^.\n]{0,30}\b(?:earn|paid|income|commission)\b",
               r"\b(?:telegram|prepaid|online)\s+tasks?\b", r"\bno\s+experience\s+(?:needed|required)\b", r"\byou\s+(?:have\s+been|are)\s+(?:selected|shortlisted|hired)\b",
               r"\b(?:rate|review)\s+(?:hotels?|restaurants?|products?|apps?|movies?)\b[^.\n]{0,40}\b(?:earn|paid|income|commission|daily|per\s+day)\b",
               r"\bearn\s+(?:up\s+to\s+)?(?:\d{1,2}\s?%\s+)?commission\b[^.\n]{0,30}\b(?:task|order|daily)", r"\bghar\s+baithe\s+(?:kamao|kamaye|kamaiye|paise|earning)\b",
               r"\b(?:roz|rozana)\s+(?:₹|rs\.?\s?)?\d[\d,]*\s+(?:kamao|kamaye|kamaiye)\b", r"(?:₹|rs\.?\s?)\d[\d,]*\s+roz\b", r"\bvideos?\s+like\s+karo\b"),
              "Easy online jobs (liking videos, rating hotels, 'tasks') are the entry point of task scams that end with you paying to 'withdraw' earnings.",
              "Check the company on its official careers page. Real employers don't pay for likes or ask for deposits."),
    Indicator("investment_lure", C.FAKE_INVESTMENT, "Guaranteed or unusually high returns", SV.HIGH, ST.STRONG, 0.82,
              (r"\b(?:guaranteed|assured|fixed)\s+(?:returns?|profits?|income)\b", r"\b(?:double|triple)\s+(?:your\s+)?(?:money|investment|amount)\b",
               r"\b\d{1,3}\s?%\s*(?:daily|weekly|monthly|per\s+(?:day|week|month))\s*(?:returns?|profits?)?\b", r"\brisk[\s-]free\s+(?:investment|returns?|profits?|trading)\b",
               r"\b(?:stock|share|crypto|forex|ipo|trading)\s+(?:tips|signals|vip\s+group)\b", r"\b(?:vip|premium)\s+(?:trading|investment|stock)\s+group\b",
               r"\binsider\s+(?:tips|information)\b", r"\bmultibagger\b", r"\bpaisa\s+double\b",
               _a(r"\b(?:earn|make|get)\s+(?:up\s+to\s+)?{AMOUNT}\s*(?:every|per|a|/)\s*(?:day|week)\b"),
               r"\b(?:passive\s+income|daily\s+profits?)\b[^.\n]{0,40}\b(?:guaranteed|assured|\d+\s?%|every\s+day)\b",
               r"\b(?:ai|automated|auto)\s+(?:crypto\s+|forex\s+)?trading\s+(?:bot|robot|software)\b[^.\n]{0,60}\b(?:profit|returns?|earn|income)\b",
               r"\b(?:cloud\s+mining|mining\s+(?:machines?|rigs?|contracts?|pool))\b[^.\n]{0,60}\b(?:earn|profit|income|returns?|daily)\b",
               _a(r"\bturn(?:ed)?\s+{AMOUNT}\s+into\s+{AMOUNT}"),
               r"\b\d{2,4}\s?%\s+(?:returns?|profits?)\s+(?:in|within)\s+(?:a|one|\d+)\s+(?:days?|weeks?|months?)\b",
               r"\b(?:guaranteed|pakka|100\s?%)\s+(?:return|munafa|profit)\b[^.\n]{0,30}\b(?:koi\s+risk\s+nahi|no\s+risk|risk[\s-]free)?",
               r"\binvest\s+karo\b[^.\n]{0,40}\b(?:pao|paao|milega|kamao|double)\b"),
              "Promises of guaranteed or very high returns are the hallmark of investment scams - the largest source of cyber-fraud losses reported in India in 2025.",
              "Invest only through SEBI-registered brokers' own apps. Check registrations on sebi.gov.in."),
    Indicator("delivery_problem", C.DELIVERY_PARCEL, "Parcel held / delivery failed", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\b(?:parcel|package|shipment|courier|consignment)\b[^.\n]{0,50}\b(?:on\s+hold|held|pending|undelivered|could\s+not\s+be\s+delivered|"
               r"failed\s+delivery|delivery\s+(?:failed|attempt)|returned|incomplete\s+address|address\s+(?:is\s+)?(?:incomplete|incorrect|invalid|wrong)|re-?delivery|customs\s+(?:duty|clearance|hold))\b",
               r"\b(?:update|confirm|verify)\s+(?:your\s+)?(?:delivery\s+)?address\b"),
              "Fake 'delivery failed - update your address' messages lead to payment or data-stealing pages. Couriers show delivery status in their own apps.",
              "Track the parcel in the courier's official app or website using the tracking number from the seller."),
    Indicator("digital_arrest", C.GOVERNMENT_IMPERSONATION, "'Digital arrest' / crime-investigation threat", SV.CRITICAL, ST.STRONG, 0.9,
              (r"\bdigital\s+(?:arrest|custody)\b", r"\b(?:you\s+are|you're)\s+under\s+(?:digital\s+)?arrest\b",
               r"\b(?:parcel|package|courier)\b[^.\n]{0,80}\b(?:drugs?|narcotics|mdma|illegal\s+items|(?:fake\s+)?passports?|weapons|contraband)\b",
               r"\bpress\s+(?:1|one|9|nine)\s+to\s+(?:talk|speak|connect)\b[^.\n]{0,40}\b(?:police|officer|cbi|customs|cyber\s+(?:crime|cell)|investigation|crime\s+branch)\b",
               r"\bjoin\s+(?:the\s+)?video\s+call\b[^.\n]{0,40}\b(?:officer|police|cbi|customs|investigation|inspector)\b",
               r"(?:डिजिटल\s+(?:अरेस्ट|गिरफ्तारी)|पार्सल[^।\n]{0,40}(?:ड्रग्स|नशीले|पासपोर्ट))",
               r"\b(?:money\s+laundering|narcotics|drug\s+trafficking)\b[^.\n]{0,60}\b(?:case|parcel|account|aadhaa?r|your\s+name)\b",
               r"\b(?:stay|remain)\s+on\s+(?:the\s+)?(?:video\s+)?call\b"),
              "'Digital arrest' does not exist in Indian law. Police, CBI, customs and courts never question or 'arrest' people over video calls or ask for money to clear a case.",
              "Hang up. Don't transfer any money. Report it on the cyber-crime helpline 1930."),
    Indicator("electricity_disconnection", C.FINANCIAL_FRAUD, "Electricity disconnection notice", SV.MEDIUM, ST.STRONG, 0.8,
              (r"\b(?:electricity|power|bijli|light)\b[^.\n]{0,60}\b(?:disconnect(?:ed|ion)?|will\s+be\s+cut|kat\s+(?:jayegi|jaegi|di\s+jayegi)|band\s+(?:ho|kar))\b",),
              "Fake disconnection notices ask you to call an 'electricity officer', who then gets you to install an app or pay. Boards don't disconnect overnight by SMS.",
              "Check your bill status in your electricity board's official app or website.",
              skip_if_near=r"maintenance|scheduled|shutdown\s+for|repair\s+work|from\s+\d{1,2}(?::\d\d)?\s*(?:am|pm)|between\s+\d"),
    Indicator("loan_lure", C.FINANCIAL_FRAUD, "Instant / pre-approved loan offer", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\b(?:pre[\s-]?approved|instant|guaranteed)\s+(?:personal\s+)?loan\b", r"\bloan\s+(?:is\s+)?(?:approved|sanctioned)\b",
               r"\b0\s?%\s+interest\b", r"\bloan\b[^.\n]{0,40}\b(?:without|no)\s+(?:documents?|cibil|credit\s+check)\b"),
              "Unsolicited instant or pre-approved loans are a common route into fee scams and predatory loan apps.",
              "Borrow only from RBI-regulated lenders through their official apps; check the lender on the RBI website."),
    Indicator("fine_waiver_claim", C.CLAIM_VERIFICATION, "Claimed waiver or discount on fines", SV.LOW, ST.WEAK, 0.7,
              (r"\b(?:waive[sd]?|waiver|rebate|maaf|discount)\b[^.\n]{0,40}\b(?:e-?challans?|challans?|fines?|penalt(?:y|ies)|dues)\b",
               r"\b(?:challans?|fines?|penalt(?:y|ies))\b[^.\n]{0,40}\b(?:waived|maaf|\d{2}\s?%\s+(?:off|discount))\b"),
              "Forwarded claims that fines will be waived or discounted are often outdated or false; they are also used to lure people to fake payment sites.",
              "Check announcements on your traffic police's official website or the Legal Services Authority."),
    # ------------------------------------------------------------------ hoax / misinformation wording
    Indicator("forward_demand", C.HOAX_MISINFORMATION, "Chain-forward request", SV.MEDIUM, ST.STRONG, 0.85,
              (r"\b(?:forward|share|send)\s+(?:(?:this|it|the)\s+)?(?:(?:message|msg|post|news|video|link|warning)\s+)?(?:(?:to|with|in|on)\s+)?(?:all|every(?:one|body)|maximum|as\s+many)\b(?:\s+(?:your\s+)?(?:people|persons|contacts|groups|friends|members|family|relatives))?",
               r"\b(?:forward|share|send)\s+(?:(?:this|it|the)\s+)?(?:(?:message|msg|post|news|video|link|warning)\s+)?(?:(?:to|with|in|on)\s+)?(?:at\s+least\s+)?(?:\d{1,3}|five|ten|fifteen|twenty)\s+(?:more\s+)?(?:whatsapp\s+)?(?:people|persons|contacts|groups|friends|members)\b",
               r"\b(?:share|forward)\s+(?:it\s+|this\s+)?(?:as\s+much\s+as\s+possible|maximum|widely)\b", r"\bforwarded\s+(?:as\s+received|many\s+times)\b",
               r"\b(?:sabko|sab\s+ko|zyada\s+se\s+zyada|jyada\s+se\s+jyada)\s+(?:forward|share|bhejo|bhejein|bheje|bata\s+do|batao)\b",
               r"\bjaldi\s+(?:forward|share)\s+kar\w*\b", r"(?:सभी\s+को\s+(?:भेजें|भेजो|शेयर)|ज्यादा\s+से\s+ज्यादा\s+(?:शेयर|भेजें))"),
              "Chain-forward requests are typical of hoaxes: they spread a claim without a checkable source. This alone doesn't mean the claim is false.",
              "Don't forward it until you've checked the claim with the official source or a fact-checker such as PIB Fact Check."),
    Indicator("share_request", C.HOAX_MISINFORMATION, "Asks you to pass the message on", SV.LOW, ST.WEAK, 0.65,
              (r"\bplease\s+(?:forward|share)\b",
               r"\b(?:forward|share|send)\s+(?:this\s+)?(?:(?:message|msg|post|news)\s+)?(?:to|with)\s+(?:all\s+)?(?:your\s+)?(?:family|friends|loved\s+ones|relatives|dear\s+ones)\b"),
              "Asking you to pass a message on is normal between friends, but it is also how unverified claims travel.",
              "Check the claim before you pass it on.", max_hits=1),
    Indicator("share_to_unlock", C.SOCIAL_ENGINEERING, "Must forward it to 'claim' or 'activate' something", SV.HIGH, ST.STRONG, 0.88,
              (r"\b(?:share|forward|send)\b[^.\n]{0,60}?\b(?:\d{1,3}|five|ten|twenty|all)\s+(?:(?:your|more)\s+)?(?:whatsapp\s+)?(?:groups?|friends|contacts|people|members)\b[^.\n]{0,60}?\bto\s+(?:claim|activate|unlock|receive|get|avail|qualify|continue|keep)\b",
               r"\bto\s+(?:claim|activate|unlock|receive|get|avail|qualify\s+for|keep)\b[^.\n]{0,60}?\b(?:share|forward|send)\b[^.\n]{0,40}?\b(?:\d{1,3}|five|ten|twenty|all)\s+(?:(?:your|more)\s+)?(?:whatsapp\s+)?(?:groups?|friends|contacts|people|members)\b",
               r"\b(?:after|once)\s+(?:you\s+)?(?:share|sharing|forward(?:ing)?)\b[^.\n]{0,60}\b(?:you\s+will|you'?ll|will\s+be)\s+(?:get|receive|be\s+credited|be\s+activated|activated|unlocked)\b",
               r"\b(?:share|forward)\b[^.\n]{0,40}\b(?:to\s+(?:activate|claim|unlock)|for\s+activation|to\s+get\s+(?:your|the)\s+(?:offer|gift|reward|recharge|prize|money))\b",
               r"\b(?:\d{1,3}|das|paanch|bees)\s+(?:groups?|logon|dosto|doston)\s+(?:me|mein|ko)\s+(?:share|bhej|forward)\w*\b[^.\n]{0,50}\b(?:milega|milenge|activate|claim|paao|payein)\b",
               r"\b(?:\d{1,3}|das|paanch|bees)\s+(?:groups?|logon|dosto|doston)\s+(?:me|mein|ko)\s+(?:share|bhej|forward)\w*\s+(?:karo|karein|kare)\s+aur\b"),
              "Being told to forward a message to a number of people or groups to 'claim' or 'activate' something is how viral scams spread themselves. "
              "Nothing is ever activated; the chain only spreads the scam, and the final page usually asks for your details or an app install.",
              "Don't forward it. Nothing is unlocked by sharing a message."),
    Indicator("sensational_authority", C.HOAX_MISINFORMATION, "Unsourced 'official' or sensational framing", SV.LOW, ST.WEAK, 0.7,
              (r"\b(?:breaking\s+news|big\s+news|good\s+news\s+for\s+all|100\s?%\s+(?:true|confirmed|genuine)|confirmed\s+news|true\s+news|very\s+important\s+(?:message|information)|it'?s\s+official)\b",
               r"\b(?:message|notice|alert|information)\s+from\s+(?:the\s+)?(?:police|army|government|govt|rbi|who|cyber\s+cell|commissioner|ministry)\b",
               r"\b(?:doctors?|scientists?|experts?)\s+(?:from|at|of)\s+(?:aiims|the\s+who|who|icmr|nasa|harvard)\b[^.\n]{0,25}\b(?:confirmed|say|said|declared|have\s+found|found)\b",
               r"\b(?:aiims|icmr|nasa|isro|unesco|who)\s+(?:has\s+|have\s+)?(?:officially\s+)?(?:confirmed|declared|announced|warned)\b"),
              "Claims of being 'official' or '100% true' without a link to an official source are common in hoaxes.",
              "Look for the same notice on the official website."),
    Indicator("free_scheme_claim", C.HOAX_MISINFORMATION, "Free money or gifts promised to everyone", SV.MEDIUM, ST.WEAK, 0.72,
              (r"\b(?:govt|government|sarkar|modi|pm)\b[^.\n]{0,40}\b(?:giving|is\s+giving|will\s+give|providing|gives)\b[^.\n]{0,30}\b(?:free|laptop|scooty|recharge|ration|money|₹|rs\.?|rupees)\b",
               r"\b(?:yojana|scheme)\b[^.\n]{0,40}\b(?:register\s+now|apply\s+now|click|claim|free)\b", r"\bfree\s+(?:recharge|data|laptop|scooty|mobile|smartphone|ration|electricity|solar)\s+(?:yojana|scheme)\b",
               r"\b(?:all|every)\s+(?:indian\s+)?(?:users?|citizens?|indians|students|farmers|women|customers|subscribers|families)\b[^.\n]{0,40}\b(?:will\s+get|get|gets|are\s+getting|can\s+get|will\s+receive|receive|eligible\s+for)\b[^.\n]{0,30}\b(?:free|rs\.?|₹|rupees|laptops?|recharge|money|cash)\b",
               r"\b(?:sabhi|sab)\s+(?:logon|users?|bharatiyon|kisanon|students)\s+(?:ko|ke)\b[^.\n]{0,30}\b(?:free|muft|₹|rs\.?)\b"),
              "Claims of free government money or gifts are a common hoax and phishing lure. Real schemes are listed on official .gov.in websites.",
              "Search for the scheme on the official .gov.in portal or PIB Fact Check before registering anywhere."),
    Indicator("policy_change_rumour", C.HOAX_MISINFORMATION, "Sudden rule-change claim", SV.LOW, ST.WEAK, 0.7,
              (r"\b(?:from\s+tomorrow|from\s+today|from\s+(?:next|this)\s+(?:week|month)|with\s+effect\s+from)\b[^.\n]{0,60}\b(?:banned|ban|charged|charges|free|blocked|deactivated|mandatory|new\s+rule|fine)\b",
               r"\b(?:kal\s+se|aaj\s+se|agle\s+(?:mahine|hafte)\s+se)\b[^.\n]{0,60}\b(?:fine|band|charge|ban|jurmana|lagega|lagenge|katega|kategi)\b",
               r"\b(?:whatsapp|facebook|gmail|instagram|google\s+pay|phonepe|upi)\s+(?:will|is\s+going\s+to)\s+(?:start\s+)?(?:charg\w*|delet\w*|band|ban\w*|shut)\b"),
              "Sudden 'from tomorrow' rule changes are a frequent misinformation pattern. Real rule changes are announced by the authority itself.",
              "Check the authority's official website or PIB Fact Check."),
    Indicator("health_misinformation", C.HOAX_MISINFORMATION, "Miracle cure or health scare", SV.MEDIUM, ST.WEAK, 0.7,
              (r"\b(?:cures?d?|kills?|prevents?|destroys?)\b[^.\n]{0,40}\b(?:cancer|covid|corona|virus|diabetes|dengue|heart\s+attack|kidney\s+stones?)\b",
               r"\b(?:doctors?\s+(?:don'?t|do\s+not)\s+want\s+you\s+to\s+know|miracle\s+(?:cure|remedy)|100\s?%\s+cure)\b",
               r"\b(?:(?:hot|warm|salt)\s+water|onion|garlic|lemon|camphor|cow\s+urine|turmeric)\b[^.\n]{0,50}\b(?:kills?|cures?|destroys?|prevents?)\b[^.\n]{0,30}\b(?:virus|covid|corona|cancer|dengue|flu|infection)\b"),
              "Miracle cures and health scares spread fast on messaging apps and are often false or misleading.",
              "Check with a doctor or the health ministry's official advisories before acting on it."),
    # ------------------------------------------------------------------ viral giveaways (scams that spread by forwarding)
    Indicator("giveaway_lure", C.LOTTERY_PRIZE, "Anniversary gift, spin-the-wheel or survey prize", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\b(?:\d{1,3}(?:st|nd|rd|th)|silver|golden|diamond|platinum)\s+anniversary\b",
               r"\banniversary\b[^.\n]{0,50}\b(?:gifts?|giveaway|free|prizes?|rewards?|celebration\s+offer)\b",
               r"\b(?:is\s+)?giving\s+away\b", r"\bgiveaway\b", r"\bfree\s+gifts?(?:\s+box(?:es)?)?\b", r"\bgift\s+box(?:es)?\b",
               r"\b(?:spin\s+(?:the\s+)?(?:wheel|and\s+win)|lucky\s+spin|scratch\s+(?:card|and\s+win)|pick\s+(?:a|your|one)\s+(?:gift|box))\b",
               r"\banswer\s+(?:\d+|a\s+few|few|some|these|four|three|five)\s+(?:simple\s+|easy\s+|quick\s+|short\s+)?questions?\b",
               r"\b(?:survey|questionnaire|quiz)\b[^.\n]{0,40}\b(?:win|reward|gift|prize|cash)\b",
               r"\b(?:only|first)\s+(?:the\s+)?(?:first\s+)?\d{2,5}\s+(?:users|people|customers|participants|winners)\b",
               r"\b(?:gifts?|rewards?|prizes?)\s+worth\s+(?:rs\.?|₹|inr)\s?[\d,]+",
               r"\bmuft\s+(?:uphaar|gift|tohfa|tohfe|inaam)\b", r"\b(?:saalgirah|salgirah)\b", r"(?:मुफ्त\s+(?:उपहार|गिफ्ट|तोहफा)|सालगिरह)"),
              "Anniversary gifts, spin-the-wheel prizes and 'answer 4 questions to win' surveys are the bait of viral giveaway scams that imitate brands like Amul, "
              "Tata, D-Mart or Amazon. Brands do run real promotions, but inside their own apps and websites.",
              "Check the brand's official website or app. A real offer will be there."),
    Indicator("free_offer_lure", C.LOTTERY_PRIZE, "Free recharge, data or subscription offer", SV.LOW, ST.WEAK, 0.7,
              (r"\bfree\s+(?:mobile\s+)?(?:recharge|data|internet|talk\s?time|netflix|(?:amazon\s+)?prime|(?:jio\s?)?hotstar|youtube\s+premium|subscription|5g\s+data)\b",
               r"\bmuft\s+(?:recharge|data|internet)\b", r"(?:मुफ्त|फ्री)\s+(?:रिचार्ज|डेटा)"),
              "Free recharges and subscriptions are common bait. Genuine telecom offers come with a recharge or plan in the operator's own app.",
              "Check the offer in your operator's or the service's official app."),
    Indicator("celebrity_giveaway", C.LOTTERY_PRIZE, "Famous person 'giving money' to everyone", SV.MEDIUM, ST.STRONG, 0.85,
              (r"\b(?:ratan\s+tata|mukesh\s+ambani|nita\s+ambani|anand\s+mahindra|sudha\s+murty|narayana\s+murthy|gautam\s+adani|elon\s+musk|bill\s+gates)\b"
               r"[^.\n]{0,50}\b(?:is\s+giving|giving|will\s+give|gives|gifting|distributing|donating)\b[^.\n]{0,40}\b(?:rs\.?|₹|rupees|free|money|cash|phones?|cars?|to\s+(?:all|every))",),
              "Messages claiming a famous businessperson is handing money or gifts to everyone are fabricated. They lead to data-harvesting pages or app installs.",
              "Ignore it. Such announcements would be on the person's or company's verified official channels."),
    # ------------------------------------------------------------------ crypto, gambling and cash-reward lures
    # Context only (INFO, no points): a mention of crypto, a casino or a promo code proves nothing by itself.
    Indicator("crypto_context", C.CRYPTO_GAMBLING, "Mentions cryptocurrency", SV.INFO, ST.WEAK, 0.9,
              (r"\b(?:crypto(?:currenc(?:y|ies))?|bitcoins?|btc|ethereum|eth|usdt|usdc|tether|binance|coinbase|blockchain|web3|defi|nfts?|"
               r"altcoins?|meme\s?coins?|airdrops?|pre-?sale|token\s+(?:launch|sale|presale)|staking|stablecoins?|solana|dogecoin|shiba\s+inu|kripto)\b",
               r"(?<![\w$])\$[A-Z]{2,10}\b(?!\s?\d)", r"(?:क्रिप्टो(?:करेंसी)?|बिटकॉइन)"),
              "Context only: cryptocurrency is mentioned. That says nothing about fraud on its own; it matters only together with other signals.",
              "", max_hits=1),
    Indicator("gambling_context", C.CRYPTO_GAMBLING, "Mentions a casino or betting", SV.INFO, ST.WEAK, 0.9,
              (r"\b(?:casinos?|betting|sportsbook|bookmakers?|bookies?|slot\s+machines?|online\s+slots?|poker|roulette|blackjack|baccarat|jackpots?|"
               r"teen\s?patti|rummy|aviator|satta|matka|colou?r\s+prediction|free\s+spins?|wager(?:ing)?|place\s+(?:a\s+|your\s+)?bets?|"
               r"bet(?:ting)?\s+(?:id|app|site|platform|account))\b", r"(?:कसीनो|कैसीनो|सट्टा|बेटिंग|जुआ)"),
              "Context only: a casino, betting or gambling game is mentioned. Gambling advertising is not fraud in itself.", "", max_hits=1),
    Indicator("promo_code", C.LOTTERY_PRIZE, "Uses a promo or bonus code", SV.INFO, ST.WEAK, 0.85,
              (r"\b(?:promo|bonus|referral|coupon|invite|voucher|special|secret|activation)\s+code\b", r"\b(?:use|enter|apply)\s+(?:the\s+)?(?:special\s+)?code\s*:?\s*[A-Z0-9]{3,15}\b",
               r"\bcode\s*:\s*[A-Z0-9]{3,15}\b", r"(?:प्रोमो\s+कोड|कोड\s*:)"),
              "Context only: the offer depends on a promotional code. Genuine shops use codes too; it matters only together with other signals.",
              "", max_hits=1),
    Indicator("reward_offer", C.LOTTERY_PRIZE, "Money, crypto or bonus credit given away", SV.MEDIUM, ST.WEAK, 0.75,
              (_a(r"\b(?:giving\s+away|give\s+away|handing\s+out|gifting|distributing|airdropping|dropping|giving)\b[^.\n!]{0,30}?{AMOUNT}"),
               _a(r"{AMOUNT}[^.\n!]{0,25}?\b(?:free\s+)?(?:bonus|reward|in\s+free\s+credits?|free\s+credits?|credits?|giveaway|airdrop)\b"),
               _a(r"\b(?:bonus|reward|airdrop|giveaway|prize|free\s+credits?)\s+(?:of|worth|up\s+to)\s+{AMOUNT}"),
               _a(r"\b(?:gets?|receives?|claim|grab|collect|wins?|earn)\s+(?:a\s+|an\s+|your\s+|the\s+)?(?:free\s+)?(?:bonus\s+of\s+)?{AMOUNT}"),
               _a(r"{AMOUNT}\s+(?:for\s+)?free\b"),
               _a(r"\bfree\s+{AMOUNT}"), r"\b(?:free|no[\s-]deposit)\s+(?:cash\s+)?(?:bonus|credits)\b",
               _a(r"{AMOUNT}\s*(?:ka|का)\s*(?:welcome\s+)?(?:bonus|बोनस|inaam|इनाम|reward|gift|गिफ्ट)"), r"(?:बोनस|इनाम)[^।\n]{0,25}(?:मिलेगा|मिलेंगे|दिया\s+जाएगा)",
               r"\bbonus\s+(?:turant\s+)?(?:milega|milenge)\b"),
              "The message offers money, cryptocurrency or 'bonus credit' for free. Real companies rarely hand out cash; on its own this is a weak sign, "
              "but it is the bait of most giveaway, casino and crypto scams.",
              "Ask yourself why a stranger would give you money. Check the offer on the company's own official website or app.",
              negate_before=NEGATION_BEFORE, negate_after=r"^\s*(?:off|discount|cash\s?back\s+on|on\s+(?:orders?|purchases?|bills?))\b"),
    Indicator("everyone_reward", C.LOTTERY_PRIZE, "Reward promised to everyone", SV.LOW, ST.WEAK, 0.75,
              (r"\b(?:giving|give|gifting|airdropping|distributing|handing\s+out|dropping)\b[^.\n!]{0,40}\b(?:to|for)\s+(?:every(?:one|body)|all\s+(?:\w+\s+){0,2}(?:users|members|players|people|followers|subscribers|participants|accounts)|every\s+(?:new\s+)?\w+)\b",
               r"\b(?:every(?:one|body)|all\s+(?:new\s+)?(?:users|members|players|accounts|followers|subscribers|participants))\s+(?:who\s+(?:[\w'-]+\s+){1,6})?(?:gets?|receives?|will\s+(?:get|receive)|can\s+claim)\b",
               r"\bevery\s+(?:new\s+|registered\s+|verified\s+|single\s+)?(?:user|member|player|account|follower|subscriber|participant|customer|person)\s+(?:who\s+\w+(?:\s+\w+){0,2}\s+)?(?:gets?|receives?|will\s+(?:get|receive))\b",
               r"\bto\s+every(?:one|body)\s+who\s+(?:registers?|signs?\s+up|joins?|creates?)\b",
               r"\b(?:har|sabhi)\s+(?:naye\s+)?(?:user|member|player|vyakti|insaan)\s+ko\b[^.\n]{0,40}\b(?:milega|milenge|bonus|reward)\b",
               r"\bsab\s?ko\b[^.\n]{0,30}\b(?:bonus|milega|milenge)\b",
               r"(?:हर|सभी)\s+(?:नए\s+)?(?:व्यक्ति|यूजर|यूज़र|सदस्य|खिलाड़ी|लोगों)\s+को[^।\n]{0,40}(?:बोनस|मिलेगा|मिलेंगे|\$|₹)"),
              "The reward is promised to everyone who takes part, which no real promotion can afford. It is a hallmark of fake giveaways.",
              "Treat 'free money for everyone' as a scam until the company confirms it on its official website.", negate_before=NEGATION_BEFORE),
    Indicator("registration_reward", C.LOTTERY_PRIZE, "Reward just for registering", SV.LOW, ST.WEAK, 0.75,
              (r"\bwho\s+(?:registers?|signs?\s+up|joins?|creates?\s+(?:an?\s+)?account)\b",
               r"\b(?:register|sign\s?up|join|create\s+(?:an?\s+|your\s+)?(?:account|id))\b[^.\n!]{0,40}\b(?:and|to)\s+(?:get|receive|claim|grab|win|earn)\b",
               r"\b(?:registration|sign[\s-]?up|welcome|joining|new[\s-]user)\s+(?:bonus|reward|credits?)\b",
               r"\bbonus\b[^.\n]{0,30}\b(?:on|for|upon|after)\s+(?:registration|registering|sign(?:ing)?\s?up|joining)\b",
               r"\b(?:who\s+)?(?:signs?\s+up|registers?|joins?)\s+(?:today|now|this\s+week)?\s*(?:gets?|receives?)\b",
               r"\bregistered\s+(?:users?|members?|players?|accounts?)\s+(?:gets?|receives?|will\s+(?:get|receive))\b",
               r"\b(?:register|join|sign\s?up)\s+(?:karne|karte)\s+(?:par|pe|hi)\b", r"(?:रजिस्टर\s+करने\s+(?:वाले|पर)|(?:जुड़ने|साइन\s?अप\s+करने)\s+(?:पर|वाले))"),
              "The reward is supposedly yours just for signing up. Fake casino, betting and crypto sites use this to get you to register, then ask for a "
              "deposit or a 'withdrawal fee' before anything can be paid out.",
              "Don't register on a site because a message promises money for it.", negate_before=NEGATION_BEFORE),
    Indicator("instant_withdrawal", C.CRYPTO_GAMBLING, "Claims the money can be withdrawn instantly", SV.LOW, ST.WEAK, 0.75,
              (r"\bwithdraw(?:n|al)?(?:\s+(?:the|your|it|this|all|winnings?|bonus|money|funds|amount|balance|usdt|crypto)){0,3}\s+(?:immediately|instantly|right\s+away|any\s?time|"
               r"in\s+(?:\d+\s+|a\s+few\s+)?(?:minutes?|seconds?|mins?)|within\s+(?:\d+\s+)?(?:minutes?|mins?|seconds?)|straight\s+to)\b",
               r"\b(?:instant|immediate|same[\s-]minute)\s+(?:withdrawals?|cash[\s-]?outs?|payouts?)\b",
               r"\b(?:can|could)\s+(?:be\s+)?(?:withdraw(?:n)?|cash(?:ed)?\s+out)\s+(?:right\s+away|immediately|instantly|any\s?time)\b",
               r"\bwithdrawable\b", r"\bcash(?:ed)?\s+out\s+(?:right\s+away|immediately|instantly)\b",
               r"\b(?:turant|turrant|instant|seedha|sidha)\s+(?:bank\s+(?:me|mein)\s+)?withdraw\b", r"\bwithdraw\s+(?:kar\s+(?:sakte|lo|lijiye|sakta)|karo)\b",
               r"(?:तुरंत|फौरन)\s+(?:निकाल|विड्रॉ)", r"निकाल\s+सकते"),
              "The message promises you can withdraw the money immediately. On its own this is common advertising; next to a free bonus it is the "
              "classic hook of fake casino and crypto sites, where the 'withdrawal' later needs a deposit or a fee.",
              "Never pay a fee or deposit to 'unlock' a withdrawal.", negate_before=NEGATION_BEFORE),
    Indicator("no_deposit_bonus", C.CRYPTO_GAMBLING, "'No deposit needed' bonus", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\bno\s+(?:deposit|wagering|kyc|verification)\s+(?:needed|required|requirements?|bonus)\b", r"\bwithout\s+(?:any\s+)?deposit\b",
               r"\b(?:bina|without)\s+deposit\b"),
              "Promising a withdrawable bonus with no deposit and no conditions is not how licensed operators work; it is how fake ones attract sign-ups.",
              "Check that the operator is licensed and that the offer is on its official site.", negate_before=NEGATION_BEFORE),
    Indicator("vanishing_post", C.SOCIAL_ENGINEERING, "Says the post or offer will soon disappear", SV.MEDIUM, ST.WEAK, 0.8,
              (r"\b(?:this|the|my)\s+(?:post|tweet|video|message|story|reel|link|offer|giveaway)\s+(?:will\s+be|is\s+going\s+to\s+be|gets?)\s+(?:deleted|removed|taken\s+down|gone)\b",
               r"\b(?:deleting|removing)\s+(?:this|the)\s+(?:post|tweet|video|message)\b", r"\b(?:post|tweet|video)\s+(?:comes?\s+down|disappears?|expires?|goes\s+down)\b",
               r"\bonly\s+the\s+(?:fastest|quickest|first)\s+(?:people|ones|users)?\b", r"\bfirst\s+come,?\s+first\s+serve[d]?\b",
               r"\b(?:limited|only)\s+(?:\d{1,5}\s+)?(?:spots?|codes?|slots?|seats?|places?)\s+(?:left|remaining|available)\b",
               r"\bpost\s+(?:\d+|ek)\s+ghante\s+(?:me|mein)\s+(?:delete|hat)\w*\b", r"\bdelete\s+ho\s+jayegi\b",
               r"(?:पोस्ट|वीडियो)[^।\n]{0,40}(?:हटा\s+दी\s+जाएगी|डिलीट\s+(?:हो\s+जाएगी|कर\s+दी\s+जाएगी))"),
              "A countdown such as 'this post will be deleted in an hour' or 'only the fastest will get it' is artificial pressure: it is there to "
              "stop you from checking before you act. Genuine offers don't vanish to hide from scrutiny.",
              "Slow down. A real offer will still be on the company's official website tomorrow."),
    Indicator("self_launch_claim", C.SOCIAL_ENGINEERING, "First-person 'I launched my own' announcement", SV.LOW, ST.WEAK, 0.7,
              (r"\b(?:launch(?:ed|ing)?|start(?:ed|ing)?|open(?:ed|ing)?|creat(?:ed|ing)|built)\s+(?:of\s+)?my\s+(?:own|new)\s+(?:\w+\s+){0,2}(?:casino|platform|token|coin|exchange|site|website|app|project|game|betting\s+(?:app|site))\b",
               r"\bannounce\s+the\s+launch\s+of\s+my\s+own\b", r"\bmy\s+own\s+(?:crypto(?:currency)?\s+)?(?:casino|betting\s+(?:app|site)|token|coin|exchange)\b",
               r"\b(?:maine|humne)\s+(?:apna|apni)\s+(?:naya\s+|nayi\s+)?(?:\w+\s+){0,2}(?:casino|app|platform|token|coin|site)\s+(?:launch|shuru)\b",
               r"(?:मैंने|हमने)\s+अपना\s+(?:नया\s+)?[^।\n]{0,20}(?:कसीनो|कैसीनो|ऐप|प्लेटफॉर्म|टोकन)\s+(?:शुरू|लॉन्च)"),
              "Posts that copy a celebrity's or influencer's voice ('I've launched my own crypto casino') are a common impersonation trick. "
              "There is no way to tell from the message who really wrote it.",
              "Check the person's verified official account before believing the announcement."),
    Indicator("partnership_claim", C.CLAIM_VERIFICATION, "Claims an unverified partnership or association", SV.LOW, ST.WEAK, 0.65,
              (r"\b(?:linked\s+to|in\s+(?:partnership|collaboration|association)\s+with|(?:partnered|partnering|teamed\s+up|collaborating)\s+with|sponsored\s+by|"
               r"backed\s+by|official\s+partner(?:ship)?\s+(?:of|with))\b", r"\bwith\s+[A-Z][\w-]+\s+(?:advertising|sponsorship|backing)\b",
               r"\blaunch\s+of\s+(?:the\s+)?[A-Z][\w-]+\s+(?:project|token|coin|platform)\b"),
              "The message claims a connection to another project, brand or person to borrow its credibility. Nothing in the message lets you verify it.",
              "Look for the partnership on both organisations' official websites.", max_hits=2),
    Indicator("crypto_send_to_receive", C.CRYPTO_GAMBLING, "'Send crypto to receive more back'", SV.CRITICAL, ST.STRONG, 0.9,
              (rf"\b(?:send|deposit|transfer)\s+(?:any\s+amount\s+(?:of\s+)?|between\s+|up\s+to\s+|from\s+)?\d[\d.,]*(?:\s*(?:and|to|-)\s*\d[\d.,]*)?\s?{CRYPTO_TICKER}\b[^\n]{{0,80}}\b(?:receive|get|back|returned|doubled?|twice)\b",
               r"\b(?:receive|get)\s+(?:it\s+)?(?:double|2x|twice(?:\s+as\s+much)?)\s+(?:back|the\s+amount|in\s+return)\b",
               rf"\bdoubl(?:e|es|ing)\s+(?:all|every|any|your)?\s*(?:the\s+)?(?:{CRYPTO_TICKER}|coins?|deposits?)\b",
               r"\b(?:send|deposit|transfer)\b[^.\n]{0,40}\bto\s+(?:verify|validate|activate|confirm)\s+(?:your\s+)?(?:wallet|address|account)\b[^.\n]{0,60}\b(?:receive|get)\b"),
              "Nobody sends back more cryptocurrency than you send them. 'Send 0.1 BTC, get 0.2 BTC back' and 'send a small amount to verify your wallet' "
              "are the signature of crypto giveaway scams: whatever you send is gone and cannot be reversed.",
              "Don't send anything. Crypto transfers cannot be reversed.", negate_before=NEGATION_BEFORE),
    Indicator("seed_phrase_request", C.OTP_SCAM, "Asks for your wallet recovery (seed) phrase", SV.CRITICAL, ST.STRONG, 0.92,
              (r"\b(?:enter|share|send|provide|give|submit|type|confirm|verify|validate|import|upload|sync|tell|paste)\b[^.\n]{0,40}\b(?:(?:your\s+)?(?:12|24|twelve|twenty[\s-]four)[\s-]word\s+(?:recovery\s+|seed\s+|secret\s+|backup\s+)?(?:phrase|words?)|(?:seed|recovery|secret|mnemonic|backup)\s+(?:phrase|words?)|private\s+keys?)\b",
               r"\b(?:seed|recovery|secret|mnemonic)\s+phrase\b[^.\n]{0,40}\b(?:to\s+(?:claim|restore|unlock|validate|verify|sync|recover|receive)|for\s+(?:verification|validation))\b",
               r"\b(?:seed|recovery|secret)\s+phrase\b[^.\n]{0,30}\b(?:verify|share|bhej|bata|daal)\w*"),
              "Your recovery (seed) phrase is the master key to your wallet. Anyone who has it can empty the wallet, and no wallet, exchange or support "
              "team ever asks for it.",
              "Never type or share your recovery phrase anywhere except when you restore your own wallet in its official app.",
              negate_before=NEGATION_BEFORE, skip_if_near=r"\b(?:no\s+(?:one|legitimate\s+\w+)|nobody|support\s+will\s+never)\b"),
    Indicator("wallet_connect_lure", C.CRYPTO_GAMBLING, "Asks you to connect or 'validate' a crypto wallet to claim something", SV.HIGH, ST.WEAK, 0.75,
              (r"\bconnect\s+(?:your\s+)?wallet\b[^.\n]{0,40}\b(?:to\s+)?(?:claim|receive|get|verify|validate|qualify|unlock|withdraw|redeem)\b",
               r"\b(?:claim|receive|get)\b[^.\n]{0,30}\b(?:airdrop|tokens?|rewards?)\b[^.\n]{0,40}\bconnect\s+(?:your\s+)?wallet\b",
               r"\b(?:validate|verify|sync|rectify|restore|unlock|whitelist|re-?activate)\s+(?:your\s+)?(?:crypto\s+)?wallet\b",
               r"\bwallet\s+(?:is|has\s+been)\s+(?:eligible|whitelisted|selected|chosen)\b", r"\bclaim\s+(?:your\s+)?(?:free\s+)?(?:airdrop|tokens|nfts?)\b"),
              "'Connect your wallet to claim' pages are wallet drainers: the approval you sign lets them move your coins. Real airdrops are announced "
              "on the project's own website and never need your recovery phrase.",
              "Don't connect your wallet to sites from messages. Revoke approvals if you already did.", negate_before=NEGATION_BEFORE),
    Indicator("pump_hype", C.FAKE_INVESTMENT, "Pump-and-dump style hype", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\b\d{2,5}\s?x\s+(?:gem|potential|returns?|coin|token|profit|pump)\b", r"\bnext\s+(?:\d{2,5}x|big|hidden)\s+(?:gem|coin|token|crypto)\b",
               r"\b(?:to\s+the\s+moon|moons?|mooning|lambo)\b", r"\bbuy\s+(?:now\s+)?before\s+(?:it|the\s+price)\s+(?:moons?|pumps?|explodes?|skyrockets?)\b",
               r"\b(?:early\s+(?:buyers|investors)|holders)\s+will\s+(?:be|become)\s+(?:millionaires|rich)\b", r"\bpre-?sale\s+(?:is\s+)?(?:live|ending|ends|closing)\b",
               r"\b(?:pump|signal)\s+(?:group|channel)\b"),
              "'100x gem', 'buy before it moons' and 'early buyers will be millionaires' are pump-and-dump hype: promoters sell to the people they "
              "attract, and the price collapses.",
              "Don't buy tokens promoted in messages or chat groups."),
    # ------------------------------------------------------------------ payment and account tricks
    Indicator("refund_lure", C.FINANCIAL_FRAUD, "Unexpected refund waiting to be claimed", SV.MEDIUM, ST.WEAK, 0.72,
              (_a(r"\brefund\s+(?:of\s+)?(?:{AMOUNT}\s+)?(?:for\s+[^.\n]{0,40}\s+)?(?:has\s+been\s+|is\s+|was\s+)?(?:approved|initiated|pending|issued|ready|due|on\s+hold)\b"),
               r"\b(?:eligible|approved)\s+for\s+(?:a\s+)?(?:tax\s+|bill\s+)?refund\b", r"\bto\s+(?:receive|get|claim|process)\s+(?:the|your)\s+refund\b",
               r"\brefund\s+(?:pane|lene)\s+ke\s+liye\b"),
              "A refund you weren't expecting that you must 'claim' is a common opening for fraud. Genuine refunds go back to the original payment "
              "method automatically.",
              "Don't share details to 'receive' a refund. Check your account in the official app.",
              skip_if_near=r"original\s+(?:payment\s+)?(?:method|source)|reflect\s+in\s+\d|(?:has|have)\s+been\s+credited|business\s+days"),
    Indicator("bank_details_request", C.PHISHING, "Asks for bank account or card details", SV.MEDIUM, ST.WEAK, 0.72,
              (r"\b(?:fill|submit|enter|share|send|update|confirm|verify|provide)\b[^.\n]{0,25}\b(?:your\s+)?(?:bank\s+(?:account\s+)?details|account\s+(?:number|details)|"
               r"ifsc(?:\s+code)?|upi\s+id|card\s+details)\b",),
              "The message asks for bank details. Refunds, prizes and scheme payments never need you to send these through a link or a message.",
              "Don't send bank details in reply to a message.", negate_before=NEGATION_BEFORE, negate_after=NEGATION_AFTER),
    Indicator("accidental_transfer", C.FINANCIAL_FRAUD, "'Money sent to you by mistake' - please return it", SV.HIGH, ST.STRONG, 0.85,
              (r"\b(?:accidentally|mistakenly|by\s+mistake|wrongly|galti\s+se)\b[^.\n]{0,40}\b(?:sent|transferred|credited|paid|bhej\w*|transfer\s+ho\w*)\b[^\n]{0,120}?\b"
               r"(?:return|send\s+(?:it\s+)?back|refund|wapas|accept|approve)\w*",
               r"\b(?:sent|transferred|credited|paid)\b[^.\n]{0,50}\b(?:by\s+mistake|mistakenly|accidentally|wrongly)\b[^\n]{0,120}?\b"
               r"(?:return|send\s+(?:it\s+)?back|refund|wapas|accept|approve)\w*"),
              "Scammers send a fake 'credited' SMS or a collect request and ask you to 'return' money that was never sent. Approving the request or paying "
              "'back' moves your own money to them.",
              "Check your balance in your bank's app. Never approve a request to 'return' money."),
    Indicator("account_alert_lure", C.PHISHING, "Account security alert that pushes you to act", SV.MEDIUM, ST.WEAK, 0.7,
              (r"\b(?:unusual|suspicious|unauthori[sz]ed|new)\s+(?:login|sign[\s-]?in|activity|access)\s+(?:detected|attempt|on\s+your\s+account|from)\b",
               r"\b(?:secure|verify|protect|restore|reactivate)\s+your\s+account\b",
               r"\bcredit\s+(?:card\s+)?limit\s+(?:has\s+been\s+|is\s+)?(?:increased|upgraded|enhanced)\b[^.\n]{0,60}\b(?:activate|verify|click|link|details)\b"),
              "Security alerts and 'limit increased - activate now' messages are used to send people to fake bank pages. Banks show real alerts in their app.",
              "Open your bank's app yourself to check; don't use links or numbers from the alert."),
    Indicator("tech_support_scare", C.SOCIAL_ENGINEERING, "Fake virus or security alert with a number to call", SV.HIGH, ST.STRONG, 0.85,
              (r"\b(?:your\s+)?(?:computer|pc|laptop|device|phone|system|windows)\s+(?:is|has\s+been|was)\s+(?:infected|hacked|compromised|locked|blocked)\b[^\n]{0,120}\b(?:call|contact|dial)\b",
               r"\b(?:microsoft|windows|apple|google)\s+(?:defender\s+|security\s+)?(?:security|support|defender)?\s*(?:alert|warning|team)\b[^\n]{0,120}\b(?:call|contact|dial)\b"),
              "Real security software and tech companies never ask you to phone a support number from a pop-up or message. The 'technician' takes "
              "remote control of your device or asks for payment.",
              "Don't call. Close the message and run your own antivirus."),
    Indicator("chat_handle", C.SOCIAL_ENGINEERING, "Moves you to a private chat or DM", SV.LOW, ST.WEAK, 0.65,
              (r"\b(?:dm|inbox|pm)\s+(?:me|us|now|for)\b", r"\b(?:telegram|whatsapp|insta(?:gram)?)\s*:?\s*@[A-Za-z][\w.]{3,31}\b", r"(?<![\w@.])@[A-Za-z][\w]{4,31}\b(?!\.)"),
              "Taking the conversation to a private chat moves you away from the platform's protections and official channels.",
              "Deal only through the company's official website or app.", max_hits=1),
    # ------------------------------------------------------------------ viral hoaxes (no money involved, but harmful)
    Indicator("viral_fear_hoax", C.HOAX_MISINFORMATION, "Alarming warning typical of viral hoaxes", SV.MEDIUM, ST.STRONG, 0.82,
              (r"\b(?:child(?:ren)?|kids?)\s+(?:kidnappers?|lifters?|kidnapping\s+gang|traffickers?)\b",
               r"\bgang\b[^.\n]{0,40}\b(?:kidnap\w*|organ\s+(?:harvest\w*|theft|trade)|drugg?(?:ing|ed)\s+(?:children|people|kids))\b",
               r"\b(?:bachcha|bachha|baccha|bachhe|bachche)\s+chor\w*\b", r"बच्चा\s+चोर",
               r"\b(?:if\s+you\s+(?:answer|pick\s+(?:it\s+)?up|receive|open|click)|answering|opening)\b[^.\n]{0,60}\b(?:(?:get|gets|will\s+be|is)\s+hacked|blast|explode|exploded|virus|data\s+(?:is\s+)?(?:stolen|copied)|bank\s+account\s+(?:is\s+)?(?:emptied|empty))\b",
               r"\b(?:all\s+)?(?:(?:whatsapp|phone|mobile)\s+)?(?:calls?|chats?|messages?)\s+(?:will\s+be|are\s+being|are\s+now)\s+(?:recorded|monitored|tracked|checked|read)\b",
               r"\bnew\s+(?:communication|whatsapp|social\s+media)\s+rules?\b", r"\b(?:three|3)\s+(?:blue|red)\s+ticks?\b",
               r"\b(?:cosmic\s+rays?|harmful\s+radiation|radiation\s+from\s+space)\b[^.\n]{0,60}\b(?:tonight|today|switch\s+off|turn\s+off|keep\s+(?:your\s+)?phones?)\b",
               r"\b(?:bad\s+luck|curse|misfortune)\b[^.\n]{0,60}\b(?:forward|send|share|ignore|break\s+the\s+chain)\b",
               r"\b(?:ignore\s+(?:it|this)|break\s+the\s+chain|don'?t\s+(?:forward|send|share)\s+(?:it|this))\b[^.\n]{0,60}\b(?:bad\s+luck|curse|misfortune|die)\b",
               r"\breceive\s+good\s+news\s+within\b"),
              "Alarming warnings that ask everyone to pass them on - kidnapping gangs, phones 'hacked by answering a call', all chats being monitored, "
              "chain letters promising luck - are among the most common viral hoaxes in India. Some have led to real violence against innocent people.",
              "Check with PIB Fact Check, your local police's official account or a fact-checker before passing it on."),
    Indicator("known_hoax_claim", C.HOAX_MISINFORMATION, "Matches a widely debunked hoax", SV.MEDIUM, ST.STRONG, 0.9,
              (r"\b(?:gps|nano|nano[\s-]?gps)\s+chip\b",
               r"\bunesco\b[^.\n]{0,80}\b(?:best|declared|greatest)\b",
               r"\b(?:earth|world|planet)\s+will\s+(?:be\s+|go\s+)?dark\b", r"\bdays\s+of\s+(?:complete\s+)?darkness\b",
               r"\b(?:whatsapp|facebook|instagram)\b[^.\n]{0,40}\b(?:will\s+(?:become|be)\s+paid|paid\s+(?:service|app)|start\s+charging|monthly\s+(?:fee|charge))\b",
               r"\b(?:account|icon|logo|ticks?)\s+(?:will\s+)?turns?\s+(?:blue|gold|red)\b", r"\bwhatsapp\s+gold\b"),
              "This repeats a claim that has been debunked many times (for example 'GPS chips in banknotes', 'UNESCO declared the best anthem' or "
              "'WhatsApp will become paid unless you forward this').",
              "Don't forward it. Search the claim on PIB Fact Check or a fact-checking site."),
)

# Statements that quote a hoax or a scam in order to debunk it ("#PIBFactCheck: this claim is fake"), news reports about
# scams and awareness messages. When present, hoax wording is not held against the message, and scam wording that the
# message only quotes or reports ("messages promising free crypto bonuses") is ignored - but scam mechanics that the
# message itself uses (its own link, its own number to call) still count.
DEBUNK = re.compile(r"(?i)\bfact[\s-]?check\w*\b[^\n]{0,200}?\b(?:fake|false|misleading|hoax|not\s+true|no\s+such|scam)\b|"
                    r"\b(?:this|the)\s+(?:claim|message|news|post|video|report|offer|viral\s+\w+)\s+(?:is|was)\s+(?:fake|false|misleading|a\s+hoax|not\s+true|baseless|a\s+scam|fraudulent)\b|"
                    r"\bno\s+such\s+(?:scheme|announcement|rule|decision|plan|offer|giveaway)\b|"
                    r"\bbeware\s+of\s+(?:\w+\s+){0,4}(?:fake|fraud\w*|scam\w*|phishing|messages|calls|links|websites|sites|apps|offers)\b|"
                    r"\b(?:scam|fraud)\s+(?:alert|warning|awareness)\b|\bfake\s+(?:news|message|claim)\b|"
                    r"\bdo\s+not\s+(?:believe|fall\s+for)\b|\bdon'?t\s+(?:believe|fall\s+for)\b|"
                    r"\b(?:is|are)\s+(?:a\s+)?(?:scams?|frauds?|hoax(?:es)?|fakes?)\b(?!\s+(?:free|proof))|"
                    r"\b(?:fraudsters|scammers|cyber\s*criminals|cheats|conmen)\s+(?:are|were|have\s+been|have)\s+(?:sending|using|targeting|calling|luring|"
                    r"posting|circulating|impersonating|creating)\b|"
                    r"\b(?:police|cyber\s+(?:cell|police|crime\s+(?:cell|branch|police))|ed|cbi)\s+(?:bust(?:ed|s)?|arrest(?:ed|s)?|nab(?:bed|s)?|crack(?:ed|s)?\s+down)\b|"
                    r"\b(?:victims|people|users)\s+(?:were|are|have\s+been)\s+(?:asked|lured|duped|cheated|told|tricked|defrauded)\b|\blured\s+(?:victims|people|users)\b|"
                    r"\b(?:cyber\s?dost|#?pib\s?fact\s?check|i4c)\b|\bnever\s+(?:posted|sent|announced|launched)\s+(?:it|this|any)\b|"
                    # warnings and news about scams: "police warn of fake casino posts", "experts caution against fraudulent apps".
                    # Deliberately not "<bank> alert": scams themselves open with "SBI Alert:".
                    r"\b(?:warn|caution)(?:s|ed|ing)?\s+(?:\w+\s+){0,3}(?:of|about|against)\s+(?:['\"\w-]+\s+){0,4}"
                    r"(?:fake|fraud\w*|scam\w*|phishing|bogus|fraudulent)\b|"
                    r"\bdo\s+not\s+(?:register|deposit|invest|sign\s+up)\s+(?:on|in|with|at)\s+(?:such|these|any|unknown)\b|"
                    r"\bnever\s+pay\s+out\b")
DEBUNKABLE = {"forward_demand", "share_request", "sensational_authority", "free_scheme_claim", "policy_change_rumour", "health_misinformation",
              "viral_fear_hoax", "known_hoax_claim"}
# Scam wording that a warning quotes ("Beware of fake KBC lottery calls ... never pay to receive prize money"). Ignored when the
# warning gives nothing to act on (no link other than gov.in / nic.in, no number to call), or when it sits inside quotation
# marks or after "messages saying / promising / claiming".
QUOTABLE_LURES = {"prize_claim", "giveaway_lure", "free_offer_lure", "celebrity_giveaway", "share_to_unlock", "fee_request", "payment_request",
                  "congratulations", "job_lure", "investment_lure", "loan_lure", "digital_arrest", "kyc_suspension", "delivery_problem",
                  "threat_of_consequence", "reward_offer", "everyone_reward", "registration_reward", "instant_withdrawal", "no_deposit_bonus",
                  "vanishing_post", "self_launch_claim", "partnership_claim", "crypto_send_to_receive", "wallet_connect_lure", "pump_hype",
                  "refund_lure", "bank_details_request", "accidental_transfer", "account_alert_lure", "tech_support_scare", "apk_install",
                  "urgency", "credential_entry", "upi_collect_trick", "seed_phrase_request", "lottery_mention", "chat_handle"}
_DOMAINISH = re.compile(r"(?i)\b(?:https?://)?((?:[a-z0-9-]+\.)+(?:com|in|net|org|xyz|top|online|site|vip|info|co|me|app|link|shop|live|icu|cc|io|"
                        r"bet|win|gg|casino|games|fun|pw|ai|club|pro))\b")
_QUOTED = re.compile("[\"“”„«»]([^\"“”„«»\n]{3,400})[\"“”„«»]"
                     r"|(?<![A-Za-z])'((?:[^'\n]|(?<=[A-Za-z])'(?=[A-Za-z])){3,400})'(?![A-Za-z])|‘([^‘’\n]{3,400})’")
_REPORTED = re.compile(r"(?i)\b(?:saying|says|claiming|claims?|promising|promises?|offering|asking\s+(?:you\s+|people\s+|users\s+|victims\s+)?to|"
                       r"that\s+(?:say|says|claim|claims|promise|promises|ask|asks|offer|offers)|which\s+(?:say|says|claims?|promises?)|"
                       r"lur(?:e|es|ed|ing)\s+(?:\w+\s+)?with|messages?\s+(?:about|like|such\s+as))\b[^.\n]{0,220}")

INDICATOR_BY_KEY = {i.key: i for i in INDICATORS}


@dataclass
class Match:
    indicator: Indicator
    start: int
    end: int
    normalized: bool = False            # found in the evasion-resistant copy, not in the text as written


def is_debunk(text: str) -> bool:
    return DEBUNK.search(text) is not None


def quoted_or_reported(text: str) -> list[tuple[int, int]]:
    """Spans the message quotes ("...") or reports ("messages promising ..."), as opposed to saying itself."""
    return [(m.start(), m.end()) for rx in (_QUOTED, _REPORTED) for m in rx.finditer(text)]


def _scan(ind: Indicator, view: str, mapper) -> list[Match]:
    hits: list[Match] = []
    for rx in ind.compiled():
        for m in rx.finditer(view):
            if m.end() == m.start():
                continue
            if ind.negate_before and re.search(ind.negate_before, view[max(0, m.start() - 40):m.start()], re.I):
                continue
            if ind.negate_after and re.search(ind.negate_after, view[m.end():m.end() + 30], re.I):
                continue
            if ind.skip_if_near and re.search(ind.skip_if_near, view[max(0, m.start() - 40):m.end() + 40], re.I):
                continue
            s, e = mapper(m.start(), m.end())
            hits.append(Match(ind, s, e, normalized=mapper is not _identity))
    return hits


def _identity(a: int, b: int) -> tuple[int, int]:
    return a, b


def find(text: str, sensitivity: str = "balanced") -> list[Match]:
    norm = normalize(text)
    views = [(text, _identity)] + ([(norm.text, norm.span)] if norm.text != text else [])
    out: list[Match] = []
    for ind in INDICATORS:
        hits: list[Match] = []
        for view, mapper in views:
            for h in _scan(ind, view, mapper):
                if not any(h.start < x.end and x.start < h.end for x in hits):
                    hits.append(h)
        hits.sort(key=lambda h: h.start)
        out.extend(hits[:ind.max_hits])
    if sensitivity == "conservative":
        out = [m for m in out if not (m.indicator.strength == ST.WEAK and m.indicator.severity == SV.LOW)]
    if is_debunk(text) or (norm.text != text and is_debunk(norm.text)):
        out = [m for m in out if m.indicator.key not in DEBUNKABLE]
        links = [d for d in _DOMAINISH.findall(text) if not d.lower().endswith((".gov.in", ".nic.in"))]
        if not links and not any(m.indicator.key == "callback_number" for m in out):
            out = [m for m in out if m.indicator.key not in QUOTABLE_LURES]
        else:
            spans = quoted_or_reported(text)
            out = [m for m in out if not (m.indicator.key in QUOTABLE_LURES and any(a <= m.start and m.end <= b for a, b in spans))]
    return out
