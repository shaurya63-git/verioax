"""Detection quality: the crypto-casino post that used to come out LOW, its variants, the new scam families, and the
genuine messages the new rules must leave alone. Offline (no link is visited)."""
import pytest

from trustguard.scam import indicators as I
from trustguard.scam.money import find_amounts
from trustguard.scam.normalize import normalize
from trustguard.schemas import RiskLevel

CASINO_POST = """I am pleased to announce the launch of my own cryptocurrency casino linked to our recent launch of the Vyro project! To celebrate this big event, I am giving away $5,600 to everyone who registers, and you can withdraw the bonus immediately.

How to claim your reward:
Go to: nyxwin.com
Enter the special promo code: BET
Receive your $5,600 bonus

This post will be deleted an hour after publication so that only the fastest people will find out about the bonus! The promotion will last for several days, so don't miss your chance!

I will also soon launch new rates on Vyro with Nyxwin advertising, so stay tuned for news!"""

HIGH_PLUS = (RiskLevel.HIGH, RiskLevel.CRITICAL)


def scan(engine, text, sender=None):
    return engine.scan_message(text, sender=sender).result


def keys(r):
    return {f.indicator for f in r.scam_findings}


# ------------------------------------------------------------------------------------------- the reported message
def test_crypto_casino_post_is_high_risk_likely_scam(engine):
    r = scan(engine, CASINO_POST)
    assert r.overall_risk in HIGH_PLUS and r.risk_score >= 50
    assert r.verdict_title.startswith("Likely scam")
    assert r.scam_type == "crypto_casino" and r.scam_type_label == "Crypto casino / betting bonus scam"


def test_crypto_casino_post_names_every_signal(engine):
    k = keys(scan(engine, CASINO_POST))
    expected = {
        "unrealistic_reward",            # 1 an unusually large financial reward
        "everyone_reward",               # 2 a cash bonus supposedly available to everyone
        "registration_reward",           # 3 obtainable simply by registering
        "instant_withdrawal",            # 4 immediate withdrawal claim
        "crypto_context",                # 5 cryptocurrency context
        "gambling_context",              # 6 casino context
        "external_claim_site",           # 7 an external website used to claim the reward
        "promo_code",                    # 8 promotional-code mechanism
        "vanishing_post",                # 9 + 10 artificial scarcity / the post will be deleted
        "partnership_claim",             # 11 unverified association between projects
        "crypto_casino_bonus",           # the combination that ties them together
    }
    assert expected <= k, expected - k


def test_crypto_casino_verdict_is_honest_about_the_unverified_site(engine):
    r = scan(engine, CASINO_POST)
    combo = next(f for f in r.scam_findings if f.indicator == "crypto_casino_bonus")
    assert "$5,600" in combo.explanation and "unverified" in combo.explanation
    assert "not on proof" in r.verdict_summary                       # no claim that the domain is known to be malicious
    assert not any(f.strength.value == "confirmed" for f in r.scam_findings)
    assert all(u.final_assessment not in HIGH_PLUS for u in r.urls)  # the link itself stays 'unverified', not 'malicious'
    assert r.urls[0].check_status == "not_checked"
    assert any("\u201c" in e for e in combo.evidence)                # quoted fragments, taken from the redacted text


def test_crypto_casino_post_is_high_under_conservative_sensitivity(settings, prefs):
    from trustguard.engine import TrustGuardEngine
    eng = TrustGuardEngine(settings, prefs.model_copy(update={"scam_sensitivity": "conservative"}), store=False)
    assert eng.scan_message(CASINO_POST).result.overall_risk in HIGH_PLUS


def test_risk_and_confidence_stay_separate(engine):
    r = scan(engine, CASINO_POST)
    assert r.overall_risk in HIGH_PLUS
    assert r.confidence_label != "High"           # the link could not be checked, so the evidence base is not complete


# ------------------------------------------------------------------------------------------- generalisation
VARIANTS = [
    "Big news! I just launched my own crypto casino. To celebrate I'm handing out $3,000 to every new member who signs up - withdraw it instantly. "
    "Visit luckyspinx.io and use promo code WIN. Hurry, this post disappears in 60 minutes!",
    "I am pleased to announce the launch of my own cryptocurrency casino! I am giving away $5,600 to everyone who registers, and you can withdraw "
    "the bonus immediately. Go to nyxwin dot com, enter promo code BET. This post will be deleted in an hour.",
    "Maine apna crypto casino launch kiya hai! Sabko register karne par $5000 bonus milega, turant withdraw kar sakte ho. nyxwin.com par jao, "
    "promo code BET daalo. Ye post 1 ghante mein delete ho jayegi, jaldi karo!",
    "Partnered with StarBet Casino: every new player gets 750 USDT free, withdrawable in minutes. Register on starbet-gift.co with bonus code STAR. "
    "Only the first 200 players!",
    "हमारे नए कैसीनो पर रजिस्टर करने "
    "वाले हर व्यक्ति को ₹20,000 का बोनस "
    "तुरंत मिलेगा, आप इसे तुरंत निकाल "
    "सकते हैं। वेबसाइट: luckyraja.win प्रोमो कोड: RAJA",
    "N E W  c r y p t o  c a s i n o: every registered user gets $2,800 FR33 b0nus, w i t h d r a w  instantly - visit spinlord dot com code SPIN. "
    "deleting this post soon",
]


@pytest.mark.parametrize("text", VARIANTS)
def test_equivalent_casino_posts_are_high(engine, text):
    r = scan(engine, text)
    assert r.overall_risk in HIGH_PLUS, (r.overall_risk, [f.indicator for f in r.scam_findings])
    assert r.scam_type == "crypto_casino"


@pytest.mark.parametrize("text,stype", [
    ("Official BTC giveaway: send 0.05 BTC to the address below and receive 0.1 BTC back within 10 minutes!", "crypto_giveaway"),
    ("Your wallet will be suspended. Validate your wallet by entering your 12-word recovery phrase at wallet-sync-help.com", "crypto_wallet"),
    ("You are eligible for 1,500 $ZORA tokens. Connect your wallet to claim at zora-claim-drop.xyz before midnight.", "crypto_wallet"),
    ("Guaranteed 4% daily profit with our AI crypto trading bot. Withdraw anytime. Join on Telegram @CryptoKingAI", "investment"),
    ("I sent Rs 3,000 to your number by mistake. Please return it, I have sent you a request, just approve it.", "upi_payment"),
    ("Your refund of Rs 1,450 is pending. To receive the refund, submit your bank account details at refund-desk.help", "refund"),
])
def test_other_crypto_and_payment_scams_are_high(engine, text, stype):
    r = scan(engine, text)
    assert r.overall_risk in HIGH_PLUS, (r.overall_risk, [f.indicator for f in r.scam_findings])
    assert r.scam_type == stype


# ------------------------------------------------------------------------------------------- precision: genuine messages
GENUINE = [
    "Bitcoin crossed $100,000 for the first time today as ETF inflows continued, according to market data.",
    "Welcome to your new wallet! Write down your 12-word recovery phrase on paper and keep it safe. Never share it with anyone.",
    "Ethereum's next network upgrade is scheduled for March. Node operators should update their clients before the fork.",
    "Royal Casino Goa: live music and dinner this Saturday. 21+ only. Please play responsibly.",
    "Get a 100% welcome bonus up to Rs 10,000 on your first deposit at our licensed sportsbook. Wagering requirements apply. 18+ only. T&C apply.",
    "Use code FIRST50 to get 50% off up to Rs 100 on your first Zomato order above Rs 199. T&C apply.",
    "Pay your electricity bill with Paytm and get Rs 50 cashback. Offer valid till 30 Nov. T&C apply.",
    "Mutual fund investments are subject to market risks. Read all scheme related documents carefully.",
    "Your refund of Rs 1,299 has been processed to your original payment method. It will reflect in 5-7 business days.",
    "You've won a scratch card on PhonePe! Open the PhonePe app to scratch it and see your cashback.",
    "Your OTP for withdrawal of Rs 5,000 from your Dream11 account is 664411. Do not share this with anyone.",
    "Delivery charges of Rs 30 apply on orders below Rs 199. Free delivery above that.",
    "For help with your order, open Help in the Zomato app or call our helpline 1800-208-9100.",
]


@pytest.mark.parametrize("text", GENUINE)
def test_genuine_messages_are_not_flagged(engine, text):
    r = scan(engine, text)
    assert r.overall_risk in (RiskLevel.LOW, RiskLevel.INCONCLUSIVE), (r.overall_risk, [f.indicator for f in r.scam_findings])


@pytest.mark.parametrize("text", [
    "News: police busted a racket that promoted a fake crypto casino. Victims were promised $5,000 sign-up bonuses and asked to pay a "
    "'withdrawal tax' to cash out.",
    "Cyber Dost: Beware of messages promising free crypto bonuses for registering on unknown websites. Report fraud at cybercrime.gov.in or call 1930.",
    "Fact check: The post claiming 'I'm giving away $5,000 to everyone who registers at bonuspalace.com, withdraw immediately' is fake.",
    "#PIBFactCheck: A message claiming the government is giving free laptops to all students is FAKE. No such scheme exists.",
    "Police warn of fake crypto casino posts promising $5,000 bonuses to everyone who registers. The sites ask for a "
    "'withdrawal fee' and never pay out. Do not register on such sites.",
    "Researchers warned about a wave of fake betting apps offering instant-withdrawal bonuses for signing up.",
])
def test_warnings_and_fact_checks_that_quote_scams_are_not_flagged(engine, text):
    r = scan(engine, text)
    assert r.overall_risk == RiskLevel.LOW, (r.overall_risk, [f.indicator for f in r.scam_findings])


@pytest.mark.parametrize("text", [
    "SBI Alert: your account will be blocked today. Your KYC has expired - update it at sbi-kyc-verify.top or call 9876543210.",
    "HDFC Bank alert: your netbanking is suspended. Share the OTP sent to you with our executive on 9123456780 to restore it.",
])
def test_scams_that_open_like_an_alert_are_still_caught(engine, text):
    """Scams open with '<Bank> Alert:' too - that wording must not be mistaken for a warning about scams."""
    assert scan(engine, text).overall_risk in HIGH_PLUS


@pytest.mark.parametrize("text", ["I bought some crypto today.", "Casino night at the club on Friday!", "Use promo code SAVE10 at checkout.",
                                  "Register for the webinar here.", "Withdrawals are processed instantly."])
def test_a_single_ingredient_is_not_fraud(engine, text):
    assert scan(engine, text).overall_risk == RiskLevel.LOW


def test_unknown_links_are_not_labelled_malicious(engine):
    r = scan(engine, "Our bakery has a new menu, have a look: https://www.example-bakery.in/menu")
    assert r.overall_risk not in HIGH_PLUS
    assert all(u.final_assessment not in (RiskLevel.HIGH, RiskLevel.CRITICAL) for u in r.urls)
    assert not any(f.indicator == "intel_listed" for f in r.scam_findings)


def test_weak_signals_alone_never_reach_high(engine):
    r = scan(engine, "Hurry! Last chance! Dear customer, click the link: https://example-shop.top/sale. Congratulations!")
    assert all(f.strength.value == "weak" for f in r.scam_findings if f.severity.value != "info")
    assert r.overall_risk not in HIGH_PLUS


# ------------------------------------------------------------------------------------------- building blocks
def test_normalisation_undoes_evasion_and_keeps_offsets():
    for raw, word in [("g i v i n g  a w a y", "giving"), ("withdr@w now", "withdraw"), ("fr​ee gift", "free"),
                      ("bоnus", "bonus"), ("nyxwin dot com", "nyxwin.com"), ("c a s h r o y a l e . c o m", "cashroyale.com")]:
        n = normalize(raw)
        i = n.text.index(word)
        s, e = n.span(i, i + len(word))
        assert raw[s:e].replace(" ", "").replace("​", "")[:1] == raw.replace(" ", "")[:1]
        assert e <= len(raw)


def test_normalisation_leaves_ordinary_tokens_alone():
    assert normalize("MH12AB1234 COVID19 Rs 500 instantly!!").text == "MH12AB1234 COVID19 Rs 500 instantly!!"


def test_money_amounts():
    got = {(a.raw, a.currency) for a in find_amounts("Win $5,600 or Rs 25,00,000 or 0.05 BTC or 1,000 USDT or 25 lakh")}
    assert {("$5,600", "usd"), ("Rs 25,00,000", "inr"), ("0.05 BTC", "btc"), ("1,000 USDT", "usdt"), ("25 lakh", "inr")} <= got
    assert find_amounts("$4.200 bonus")[0].value == 4200


def test_negated_requests_are_ignored():
    found = {m.indicator.key for m in I.find("Never share your seed phrase or OTP with anyone. No one will ask you to connect your wallet to claim rewards.")}
    assert not ({"seed_phrase_request", "credential_request", "wallet_connect_lure"} & found)


# ---------------------------------------------------------------------------------------------- card details asked for directly
@pytest.mark.parametrize("text", [
    "please provide your hdfc credit card 16 digit number, cvv, expiry month/year\ni want to do some changes in the card",
    "Sir I am calling from SBI card department, kindly send your card number and CVV to update your credit limit",
    "Apna debit card number, expiry aur CVV bhejo, card upgrade karna hai",
    "Share the 3 digit number on the back of your card and the expiry date to stop the deduction",
])
def test_requests_for_card_number_cvv_or_expiry_are_critical_without_a_link(engine, text):
    r = scan(engine, text)
    assert r.overall_risk == RiskLevel.CRITICAL and r.scam_type == "bank_phishing"
    assert "card_details_request" in {f.indicator for f in r.scam_findings}


@pytest.mark.parametrize("text", [
    "HDFC Bank never asks for your card number, CVV, expiry date or OTP. Do not share them with anyone.",
    "Never share your CVV or card details with anyone, even if they claim to be from the bank.",
    "Your HDFC Credit Card ending 4321 has been used for Rs 2,499 at Amazon. Not you? Call 1800-202-6161.",
])
def test_card_safety_advice_and_card_alerts_stay_low(engine, text):
    assert scan(engine, text).overall_risk == RiskLevel.LOW
