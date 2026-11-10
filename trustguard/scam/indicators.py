"""Message-level scam and hoax indicators.

Each indicator is a small, explainable rule: the phrases it looks for (English, Hinglish and some Hindi), the category
it supports, how severe it is, and - importantly - how much it proves on its own (``Strength``):

* WEAK   - common in scams but also in honest messages (urgency, "Dear customer", "click the link");
* STRONG - something legitimate senders practically never do (asking for an OTP, a fee to release a prize);
* CONFIRMED is never produced from wording alone; it needs verifiable evidence (threat intelligence, a page that asks
  for a CVV on an impersonating domain).

Weak indicators alone can never push a message above MEDIUM risk (see ``trustguard.risk``), which is what stops every
urgent office message from being called a scam.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..schemas import ScamCategory as C
from ..schemas import Severity as SV
from ..schemas import Strength as ST


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


SECRET = (r"(?:otp|one[\s-]?time\s+pass(?:word|code)|verification\s+code|security\s+code|upi\s*pin|m-?pin|atm\s*pin|\bpin\b|cvv|"
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

INDICATORS: tuple[Indicator, ...] = (
    # ------------------------------------------------------------------ pressure
    Indicator("urgency", C.SOCIAL_ENGINEERING, "Urgency / pressure tactic", SV.LOW, ST.WEAK, 0.75,
              (r"\b(?:urgent(?:ly)?|immediately|right\s+away|act\s+now|hurry|asap|without\s+delay|at\s+the\s+earliest)\b",
               r"\b(?:within|in\s+the\s+next|in)\s+(?:\d{1,2}|twenty[\s-]four|forty[\s-]eight|two|few)\s*(?:hours?|hrs?|minutes?|mins?)\b",
               r"\b(?:last\s+(?:date|day|chance|reminder|warning)|final\s+(?:notice|reminder|warning|chance))\b",
               r"\bexpir(?:es|ing|y)\s+(?:today|tonight|soon|in\s+\d+)\b", r"\b(?:before|by)\s+(?:midnight|tonight|end\s+of\s+(?:the\s+)?day)\b",
               r"\b(?:turant|turrant|abhi|jaldi|aaj\s+hi|fauran|jald\s+se\s+jald)\b", r"(?:तुरंत|अभी|जल्दी|आज\s+ही)"),
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
               r"insurance|gst|tds|release|courier|transfer|unlock|kyc)\s+(?:fee|fees|charge|charges|deposit|amount)\b",
               r"\b(?:advance|upfront)\s+(?:payment|fee|amount)\b",
               r"\bpay\b[^.\n]{0,40}\bto\s+(?:claim|receive|release|unlock|activate|get\s+your)\b"),
              "Being asked to pay a fee to receive money, a prize, a parcel or a job is the signature of advance-fee fraud.",
              "Don't pay. Real prizes, refunds and jobs never require an upfront fee.",
              negate_before=NEGATION_BEFORE),
    Indicator("upi_collect_trick", C.FINANCIAL_FRAUD, "Asks for your UPI PIN to 'receive' money", SV.CRITICAL, ST.STRONG, 0.9,
              (r"\b(?:to\s+(?:receive|get|claim|credit)|for\s+(?:receiving|refund|cashback|credit))\b[^.\n]{0,60}\b(?:enter|scan|approve|accept|put|use)\b[^.\n]{0,25}\b(?:upi\s+)?(?:pin|qr)\b",
               r"\b(?:enter|approve)\b[^.\n]{0,30}\bpin\b[^.\n]{0,40}\b(?:receive|refund|cashback|credited|credit)\b"),
              "You never need to enter your UPI PIN or scan a QR code to receive money. Entering the PIN sends money out of your account.",
              "Decline the request. Only enter your UPI PIN when you are the one paying."),
    Indicator("credential_request", C.OTP_SCAM, "Asks for an OTP, PIN, CVV or password", SV.CRITICAL, ST.STRONG, 0.88,
              (rf"\b{ASK}\b[^.\n]{{0,30}}\b{SECRET}", rf"\b{SECRET}\b[^.\n]{{0,25}}\b(?:share|send|bata(?:o|yein|ye)?|bhej(?:o|ein|e)?|batana|bhejna)\b"),
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
               r"\b(?:update|complete|verify|re-?verify)\s+(?:your\s+)?(?:kyc|pan|aadhaa?r|account\s+details|bank\s+details)\b",
               r"\b(?:pan|aadhaa?r)\b[^.\n]{0,25}\b(?:not\s+linked|link(?:ed)?\s+(?:now|immediately|today))\b",
               r"\b(?:account|card|yono|net\s?banking|wallet)\b[^.\n]{0,30}\b(?:blocked|suspended|frozen|deactivated|on\s+hold|locked)\b",
               r"\b(?:account|card|kyc|wallet|profile)\b[^.\n]{0,20}\b(?:needs?|requires?|is\s+pending)\s+(?:urgent\s+)?(?:verification|re-?verification|update|re-?kyc)\b"),
              "Warnings that your KYC has expired or your account will be blocked are the most common banking phishing lure. Banks ask you to use their own app or visit a branch.",
              "Open your bank's app yourself, or call the number printed on your card."),
    Indicator("apk_install", C.PHISHING, "Asks you to install an app from a file or link", SV.HIGH, ST.STRONG, 0.85,
              (r"\.apk\b", r"\b(?:download|install)\s+(?:this|the|our|attached|below|given)?\s*(?:app|application|apk|file)\b"),
              "Apps sent as files or links (.apk) bypass Play Store checks. Fake 'RTO Challan' and 'bank' apps read your SMS, OTPs and card details.",
              "Don't install apps from messages. Get official apps from the Play Store only.",
              skip_if_near=r"play\s?store|app\s?store|google\s+play"),
    Indicator("remote_access", C.SOCIAL_ENGINEERING, "Asks you to install remote-access / screen-sharing app", SV.CRITICAL, ST.STRONG, 0.9,
              (r"\b(?:anydesk|any\s+desk|teamviewer|team\s+viewer|quick\s?support|rustdesk|airdroid|ammyy|ultraviewer)\b",
               r"\bscreen\s?(?:share|sharing)\b", r"\b(?:install|download)\b[^.\n]{0,30}\b(?:remote|support)\s+app\b"),
              "Remote-access apps let a stranger see and control your phone, including your banking apps and OTPs.",
              "Don't install screen-sharing or remote-access apps at anyone's request."),
    Indicator("callback_number", C.SOCIAL_ENGINEERING, "Asks you to call or message a personal number", SV.LOW, ST.WEAK, 0.7,
              (r"\b(?:call|contact|whatsapp|reach|dial|message|sampark\s+karein|call\s+karein)\b[^.\n]{0,25}(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b",
               r"\b(?:call|contact|whatsapp|dial)\b[^.\n]{0,25}(?:\+?91[\s-]?)?[6-9]\d{2}[\s-]?\d{3}[\s-]?\d{4}\b"),
              "You're asked to call or message a mobile number. Organisations use published helpline numbers, not personal mobiles.",
              "Use only the helpline number on the organisation's official website, card or bill."),
    Indicator("click_link_cta", C.PHISHING, "Tells you to click a link", SV.LOW, ST.WEAK, 0.7,
              (r"\b(?:click|tap|open|visit|go\s+to|follow)\b[^.\n]{0,20}\b(?:the\s+|this\s+|below\s+)?(?:link|url|website|here)\b",
               r"\blink\s+(?:par|pe)\s+(?:click|tap)\s+(?:karein|karo|kare)\b", r"लिंक\s+पर\s+क्लिक"),
              "Messages that push you to a link want you on a page they control.", "Type the official address yourself instead of tapping the link.",
              max_hits=1),
    # ------------------------------------------------------------------ lures
    Indicator("prize_claim", C.LOTTERY_PRIZE, "Prize, lottery or reward claim", SV.MEDIUM, ST.STRONG, 0.8,
              (r"\b(?:lucky\s+draw|lottery|jackpot|bumper\s+prize|lucky\s+winner|grand\s+prize|prize\s+money|winning\s+amount)\b",
               r"\byou\s+(?:have\s+)?(?:won|been\s+selected\s+for\s+(?:a\s+)?(?:prize|reward|gift)|are\s+(?:the\s+)?(?:lucky\s+)?winner)\b",
               r"\bclaim\s+(?:your\s+)?(?:prize|reward|gift|cashback|winnings|lottery)\b", r"\bfree\s+(?:iphone|laptop|mobile|scooty|bike|car|tv|smartphone)\b",
               r"\b(?:aapne|apne)\b[^.\n]{0,25}\b(?:jeeta|jeete|jeet\s+liya|jeeti)\b", r"\binaam\b", r"(?:लॉटरी|इनाम|आपने\s.{0,25}जीत)"),
              "Unexpected prizes, lotteries and rewards you never entered are a classic lure; the 'prize' is used to extract a fee or your details.",
              "Ignore it. You can't win a lottery you never entered."),
    Indicator("congratulations", C.LOTTERY_PRIZE, "Congratulatory opener", SV.LOW, ST.WEAK, 0.6,
              (r"\b(?:congratulations|congrats)\b", r"बधाई\s+हो"), "Often used to open prize scams, but also common in honest messages.", "", max_hits=1),
    Indicator("job_lure", C.FAKE_JOB, "Easy-money job offer", SV.MEDIUM, ST.WEAK, 0.75,
              (r"\b(?:work\s+from\s+home|part[\s-]?time\s+(?:job|work|income)|home[\s-]based\s+(?:job|work))\b",
               r"\bearn\s+(?:up\s+to\s+)?(?:rs\.?|₹|inr)?\s?\d[\d,]*\s*(?:per|a|/)\s*(?:day|hour|week)\b", r"\bdaily\s+(?:income|earning|payment|salary|payout)\b",
               r"\b(?:like|subscribe|rate|review)\b[^.\n]{0,20}\b(?:videos?|youtube|hotels?|products?|posts?)\b[^.\n]{0,30}\b(?:earn|paid|income|commission)\b",
               r"\b(?:telegram|prepaid|online)\s+tasks?\b", r"\bno\s+experience\s+(?:needed|required)\b", r"\byou\s+(?:have\s+been|are)\s+(?:selected|shortlisted|hired)\b"),
              "Easy online jobs (liking videos, rating hotels, 'tasks') are the entry point of task scams that end with you paying to 'withdraw' earnings.",
              "Check the company on its official careers page. Real employers don't pay for likes or ask for deposits."),
    Indicator("investment_lure", C.FAKE_INVESTMENT, "Guaranteed or unusually high returns", SV.HIGH, ST.STRONG, 0.82,
              (r"\b(?:guaranteed|assured|fixed)\s+(?:returns?|profits?|income)\b", r"\b(?:double|triple)\s+(?:your\s+)?(?:money|investment|amount)\b",
               r"\b\d{1,3}\s?%\s*(?:daily|weekly|monthly|per\s+(?:day|week|month))\s*(?:returns?|profits?)?\b", r"\brisk[\s-]free\s+(?:investment|returns?|profits?|trading)\b",
               r"\b(?:stock|share|crypto|forex|ipo|trading)\s+(?:tips|signals|vip\s+group)\b", r"\b(?:vip|premium)\s+(?:trading|investment|stock)\s+group\b",
               r"\binsider\s+(?:tips|information)\b", r"\bmultibagger\b", r"\bpaisa\s+double\b"),
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
               r"\b(?:parcel|package|courier)\b[^.\n]{0,60}\b(?:drugs?|narcotics|mdma|illegal\s+items|fake\s+passports?)\b",
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
               r"\b(?:sabko|sab\s+ko|zyada\s+se\s+zyada|jyada\s+se\s+jyada)\s+(?:forward|share|bhejo|bhejein|bheje)\b", r"(?:सभी\s+को\s+(?:भेजें|भेजो|शेयर)|ज्यादा\s+से\s+ज्यादा\s+(?:शेयर|भेजें))"),
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

# Statements that quote a hoax in order to debunk it ("#PIBFactCheck: this claim is fake"). When present, the hoax
# wording is not held against the message - but scam mechanics (share-to-unlock, prizes, payment requests) still are.
DEBUNK = re.compile(r"(?i)\bfact[\s-]?check\w*\b[^.\n]{0,120}\b(?:fake|false|misleading|hoax|not\s+true|no\s+such)\b|"
                    r"\b(?:this|the)\s+(?:claim|message|news|post|video|report)\s+is\s+(?:fake|false|misleading|a\s+hoax|not\s+true|baseless)\b|"
                    r"\bno\s+such\s+(?:scheme|announcement|rule|decision|plan)\b|\bbeware\s+of\b|\b(?:scam|fraud)\s+alert\b|\bfake\s+(?:news|message|claim)\b|"
                    r"\bdo\s+not\s+(?:believe|fall\s+for)\b|\bdon'?t\s+(?:believe|fall\s+for)\b")
DEBUNKABLE = {"forward_demand", "share_request", "sensational_authority", "free_scheme_claim", "policy_change_rumour", "health_misinformation",
              "viral_fear_hoax", "known_hoax_claim"}
# Scam wording that a warning quotes ("Beware of fake KBC lottery calls ... never pay to receive prize money"). Ignored only
# when the warning also gives nothing to act on: no link (other than gov.in / nic.in) and no number to call.
QUOTABLE_LURES = {"prize_claim", "giveaway_lure", "free_offer_lure", "celebrity_giveaway", "share_to_unlock", "fee_request", "payment_request",
                  "congratulations", "job_lure", "investment_lure", "loan_lure", "digital_arrest", "kyc_suspension", "delivery_problem",
                  "threat_of_consequence"}
_DOMAINISH = re.compile(r"(?i)\b(?:https?://)?((?:[a-z0-9-]+\.)+(?:com|in|net|org|xyz|top|online|site|vip|info|co|me|app|link|shop|live|icu|cc|io))\b")

INDICATOR_BY_KEY = {i.key: i for i in INDICATORS}


@dataclass
class Match:
    indicator: Indicator
    start: int
    end: int


def find(text: str, sensitivity: str = "balanced") -> list[Match]:
    out: list[Match] = []
    for ind in INDICATORS:
        hits: list[Match] = []
        for rx in ind.compiled():
            for m in rx.finditer(text):
                if m.end() == m.start():
                    continue
                if ind.negate_before and re.search(ind.negate_before, text[max(0, m.start() - 40):m.start()], re.I):
                    continue
                if ind.negate_after and re.search(ind.negate_after, text[m.end():m.end() + 30], re.I):
                    continue
                if ind.skip_if_near and re.search(ind.skip_if_near, text[max(0, m.start() - 40):m.end() + 40], re.I):
                    continue
                if any(m.start() < h.end and h.start < m.end() for h in hits):
                    continue
                hits.append(Match(ind, m.start(), m.end()))
        hits.sort(key=lambda h: h.start)
        out.extend(hits[:ind.max_hits])
    if sensitivity == "conservative":
        out = [m for m in out if not (m.indicator.strength == ST.WEAK and m.indicator.severity == SV.LOW)]
    if DEBUNK.search(text):
        out = [m for m in out if m.indicator.key not in DEBUNKABLE]
        links = [d for d in _DOMAINISH.findall(text) if not d.lower().endswith((".gov.in", ".nic.in"))]
        if not links and not any(m.indicator.key == "callback_number" for m in out):
            out = [m for m in out if m.indicator.key not in QUOTABLE_LURES]
    return out
