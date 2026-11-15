# How Verioax scores a scan

Verioax reports two separate numbers:

- **Risk score (0–100) and level:** how dangerous the content looks.
- **Confidence (0–1):** how much evidence the verdict rests on.

A message can be high risk with medium confidence. A typical case is a clear impersonation pattern whose link could not
be visited.

The scoring is deterministic. The same input with the same settings always produces the same score, and every result
records a hash of the settings it used (`processing.config_hash`). The implementation is `trustguard/risk.py`.

## 1. Findings

Every engine produces findings. A finding has these fields:

| Field | Values | Meaning |
|---|---|---|
| severity | info · low · medium · high · critical | How bad it is if the finding is true |
| strength | weak · strong · confirmed | How strongly it points to fraud |
| confidence | 0–1 | How reliable the detector is for this pattern |
| category | one of 17 | e.g. government impersonation, phishing, hoax, crypto & gambling, malicious app |
| families | e.g. reward · destination · context · registration | the independent kinds of evidence a combination rule rests on (see 5b) |

What each strength means:

- **Weak:** common in scams, but also in honest messages. Examples: urgency words, "pay now", a `.vip` domain.
- **Strong:** rarely legitimate. Examples: a lookalike of a bank's domain, or a government body texting from a personal
  mobile number.
- **Confirmed:** direct evidence. Examples: a match on a threat-intelligence blocklist or the local indicator list, or the
  live page asking for card number and CVV.

`info` findings give context and add no points. Examples: a link was found, an amount was mentioned, cryptocurrency or
a casino is mentioned, a promo code is used. The result screen lists them separately under "Context noted - not counted
in the score".

## 2. Points

```
points(finding) = SEVERITY_POINTS[severity] × STRENGTH_FACTOR[strength] × confidence
```

| Severity | Points |  | Strength | Factor |
|---|---|---|---|---|
| critical | 45 | | confirmed | 1.4 |
| high | 28 | | strong | 1.0 |
| medium | 14 | | weak | 0.5 |
| low | 6 | | | |
| info | 0 | | | |

**Diminishing returns per category.** Within one category, findings are sorted by points. The strongest counts in full,
the second counts half, the third a quarter, and so on. Ten urgency words are not ten times as bad as one.

The same indicator matching several times in a message is **one** finding. Every place it matched is still highlighted.

**Mitigations** subtract points for signs that a message is genuine. They apply **only if there is no strong or
confirmed high/critical finding**. They can therefore lower a borderline score, but never explain away real evidence.

| Mitigation | Points |
|---|---|
| Every link points to a verified official or restricted-registry domain (`gov.in`, `bank.in`, the `.sbi` TLD, …), and nothing dangerous is requested | −12 |
| Sent from a registered government SMS header (`-G` suffix) and the message claims a government sender | −10 |
| Sent from a transactional or service header that matches the bank it names | −8 |
| Contains the standard "do not share your OTP" advisory | −5 |
| Carries the terms, age (18+) or market-risk disclosures that genuine promotions include | −4 |
| Points you to the official app, with no link, number or payment request | −4 |

## 3. Score and level

```
raw   = Σ over categories of Σ points / 2^rank  − mitigations
score = round(100 × (1 − e^(−raw / 45)))
```

The exponential saturates smoothly, so the score never exceeds 100, and one more weak signal moves a high score less than
a low one.

| Sensitivity (Settings) | MEDIUM from | HIGH from | CRITICAL from |
|---|---|---|---|
| conservative | 30 | 55 | 80 |
| balanced (default) | 25 | 50 | 75 |
| aggressive | 20 | 45 | 70 |

## 4. Guard rails

After the threshold, these rules apply. When a rule moves the level, the score moves to that level's edge, so the score
and the level always agree.

| Rule | Effect |
|---|---|
| Confirmed critical finding | Level is **CRITICAL** |
| Confirmed high, or strong critical, finding | Level is at least **HIGH** |
| Any other strong or confirmed finding of medium severity or worse | Level is at least **MEDIUM**. A strong signal means honest senders practically never do this, so a short message can't score it down to LOW. |
| A complete attack pattern: a strong or confirmed, high or critical combination finding built from **three or more independent evidence families** | Level is at least **HIGH**. This lets a message justify HIGH on its own, without any proof about the website. |
| Only weak findings | Level is at most **MEDIUM**. Weak signals alone never make a HIGH verdict. |
| The content hinges on a link that could not be verified, and nothing else raised the level | **INCONCLUSIVE** instead of LOW |

"Verified" means at least one of these is true:
- the link was visited
- it is on an official or restricted-registry domain
- a live or cached threat-intelligence lookup returned a real answer

**Each link also gets its own verdict.** It is computed from the findings attached to that link, including any
combination rule that involves it.

## 5. Combination rules

These rules look across engines and recognise a complete scam pattern rather than isolated words.

| Rule | Fires when | Result |
|---|---|---|
| Impersonation + request + unofficial link | The message claims to be an organisation and asks for payment or details, and its link goes to a domain the organisation doesn't own | critical · strong |
| Claimed sender ≠ link owner | As above, but without a request | high · strong for government and banks, otherwise medium · weak |
| Prize + fee | A prize claim and a payment or fee request | high · strong |
| Job + fee | A job offer and a payment request | high · strong |
| Job + private chat | A job offer that links to a WhatsApp or Telegram chat | medium · weak |
| Loan + fee | A loan offer with an upfront processing fee | high · strong |
| Delivery problem + payment or link | A parcel-on-hold story with a fee or an unofficial link | high · strong |
| KYC warning + link | "Account blocked / KYC expired" with a link (no named organisation) | high · strong |
| Investment + private contact | High returns pitched through a chat, a personal number or an unknown site | high · strong |
| Disconnection + callback | An electricity disconnection threat with a mobile number to call | high · strong |
| Card details + link | Asks you to type card or banking details on an unofficial link | high · strong |
| Official identity + personal number | A bank or government message that asks you to call a mobile number | high · strong if combined with a threat, otherwise medium · weak |
| Viral giveaway | A prize, gift, free recharge or free-scheme offer that you must forward or share to "unlock" | high · strong |
| Free offer + unknown link | A prize or free offer whose link goes to a domain that belongs to no known brand or government body | high · strong |
| Prize + personal contact | A prize claimed by calling a mobile number or messaging on WhatsApp or Telegram (the "KBC lottery" pattern) | high · strong |
| Unsourced claim + forward request | A hoax-type claim (fear hoax, debunked claim, health or policy rumour, fake scheme) combined with a request to forward it | medium · strong |

Rules added in this version:

| Rule | Fires when | Result |
|---|---|---|
| Crypto / casino bonus | A reward, plus at least two independent mechanics (offered to everyone · just for registering · instantly withdrawable or "no deposit" · the post will disappear · an unverified launch or partnership claim · an unusually large amount), plus a place to claim it (an unverified site, a chat, a promo code, a number), plus a crypto or gambling context | high · strong |
| Cash for signing up | The same without the crypto or gambling context: a reward offered to everyone or for registering, plus a large amount, an instant withdrawal, scarcity or a persona claim, plus a place to claim it | high · strong |
| Crypto or gambling bonus (weak) | A reward in a crypto or gambling context with a destination or one mechanic, not enough for the rules above | medium · weak |
| Reward claimed on an outside site | One of the reward rules fired and the claim site is an unverified domain | low · weak (it explains the link; it is not proof the site is malicious) |
| Wallet drainer | "Connect / validate / sync your wallet" or a seed-phrase request with an unknown site | high · strong |
| Fake customer care | "<Brand> customer care / helpline" on a personal mobile number | high · strong |
| Account warning + callback | "Your account is blocked / KYC pending" with a mobile number to call | high · strong |
| Sent by mistake | A "money sent to you by mistake" story with a request to approve, return or share a code | high · strong |
| Fake security alert | A virus / hacked-account scare with a support number to call | high · strong |
| Refund + request | A refund that needs your card, UPI PIN, OTP or a link | high · strong |

Disclosures change the bar: when a promotion carries the usual T&C, 18+ or market-risk text, the reward rules need three
mechanics instead of two.

**Fact-checks and warnings are not hoaxes.** When a message reads as a debunk ("FAKE", "PIB Fact Check", "beware of
messages claiming…"), the hoax indicators that it quotes don't count against it. Prize and free-offer wording is also
ignored in that case, as long as the message carries no link and no number to call. Wording inside quotation marks or
reported speech ("they say 'you won Rs 25 lakh'") is treated the same way, and a link that is only quoted in a warning
is not treated as one the message asks you to open.

## 5b. Independent evidence families

A combination finding records which **kinds** of evidence it rests on. For the crypto-casino rule these are: reward,
destination, context and each mechanic. Two phrases that say the same thing ("free bonus" and "bonus for free") are one
signal, not two. The complete-pattern floor in section 4 needs three families or more.

The same idea keeps single ingredients harmless:

- A crypto mention alone is a 0-point context note.
- A casino advertisement alone is a 0-point context note.
- A promo code alone is a 0-point context note.
- A large amount alone is a weak signal.

Only the combination of a reward, a mechanic that makes it implausible, and somewhere to hand over your details or money
produces a strong finding.

## 5c. Spelling tricks, amounts and languages

Indicators are matched twice: on the text as written, and on a normalised copy. The normalised copy has:

- zero-width characters removed
- Unicode compatibility forms and lookalike letters (Cyrillic, Greek, full-width) folded
- leetspeak undone (`fr33 b0nus`)
- spaced-out letters joined (`c a s i n o`)
- `nyxwin dot com` read as a domain

Matches from the normalised copy are mapped back to the original text, so the highlighted fragment is what the person
actually received. Normalisation can only add matches, never remove one.

Amounts are parsed in rupees (Rs, ₹, lakh, crore, `rupaye`), dollars, euros, pounds and crypto tickers (BTC, ETH, USDT,
...), including Indian digit grouping and `$4.200`-style separators. They are converted with rough fixed rates, only to
decide whether a reward is "unusually large" (≥ ₹5,000 equivalent). The number is never shown as a precise conversion.

Hindi (Devanagari) and Hinglish wordings exist for the reward, registration, withdrawal, scarcity and urgency
indicators.

## 5d. Scam type

Next to the category of each finding, every scan gets one **scam type**: the pattern the findings add up to. Examples:
crypto casino / betting bonus, crypto giveaway, wallet drainer, UPI payment fraud, OTP theft, fake customer support,
fake e-challan, digital arrest, job scam, investment scam, bank phishing, malicious app.

The type is chosen by ordered rules over the matched indicators, the claimed organisation and hints from the links. A
link like `binance-bonus.top` suggests a crypto giveaway. The type is shown only when the level is MEDIUM or worse. It
explains the verdict and never changes the score.

## 5a. Page content

When live checks are on, the text of the visited page is checked too, unless the page is on an official domain or reads
as a fact-check.

| Signal | Fires when | Result |
|---|---|---|
| Share to claim | The page offers a prize or gift and asks you to share it with friends or groups first | high · confirmed |
| Fake scheme form | The page presents a government scheme and asks for Aadhaar, bank or card details | critical · strong |
| Fee to release | The page asks for a processing, delivery or registration fee | high · strong |
| Prizes or free offers | The page talks about prizes, gifts or free recharges | medium · weak |
| Known hoax | The page repeats a widely debunked claim or a viral fear hoax | medium · strong for a known claim, otherwise weak |
| Easy money | The page pitches high returns, easy online work or instant loans | medium · weak |

The link's own name is checked as well. A government scheme name in a domain that isn't `.gov.in` or `.nic.in`
(`pm-laptop-yojana.in`), or a domain made of giveaway words (`amul-anniversary-gift.blogspot.com`), is a strong signal
when it comes with a brand name, a throwaway ending or an action word such as "apply" or "register".

## 6. Confidence

Confidence starts from the evidence that was actually available:

| Situation | Confidence |
|---|---|
| INCONCLUSIVE | 0.30 |
| No meaningful findings | 0.55, +0.10 if every link was visited, +0.05 if online threat intelligence answered, −0.10 for very short text. **Capped at 0.75.** Absence of evidence is never high confidence. |
| Findings present | 0.50, +0.08 per independent source family with medium-or-worse findings (message, sender, link, page, intel, combination; at most 3 count), +0.15 if anything is confirmed (or +0.07 if strong), +0.08 × share of links visited, −0.10 if no link could be visited, −0.10 for very short text. Clamped to 0.20–0.97. |

Labels: **High** ≥ 0.75, **Medium** ≥ 0.50, otherwise **Low**.

## 7. Worked example

This is the built-in *Fake e-challan* sample, in local mode (no live checks), sent from `+91 98765 43210`:

> Dear Ravi Kumar, your vehicle MH12AB1234 has a pending e-challan of Rs 590. Pay immediately to avoid licence suspension
> and court proceedings: https://echallan-pay.vip/pay

| Finding | Category | Severity · strength · conf. | Points |
|---|---|---|---|
| Claims to be Parivahan, asks for payment, links elsewhere | government impersonation | critical · strong · 0.92 | 41.40 |
| Uses the name Parivahan in an unofficial domain | government impersonation | critical · strong · 0.88 | 39.60 → ×½ = 19.80 |
| Claims to be Parivahan but sent from a personal mobile number | government impersonation | high · strong · 0.88 | 24.64 → ×¼ = 6.16 |
| Asks you to pay ("pending e-challan" … "Pay immediately", one finding) | urgent payment | medium · weak · 0.75 | 5.25 |
| Threat of penalty, blocking or legal action | social engineering | medium · weak · 0.75 | 5.25 |
| Urgency / pressure tactic | social engineering | low · weak · 0.75 | 2.25 → ×½ = 1.13 |
| Frequently abused ending (.vip) | suspicious link | low · weak · 0.65 | 1.95 |
| Mentions an amount of money; link in the message | — | info | 0 |

```
raw   = (41.40 + 19.80 + 6.16) + 5.25 + (5.25 + 1.13) + 1.95 = 80.94
score = round(100 × (1 − e^(−80.94/45))) = 83   →  CRITICAL (≥ 75)
```

Confidence:
- Medium-or-worse findings come from four source families (message, sender, link, combination). Three count, giving
  +0.24.
- At least one finding is strong, giving +0.07.
- The link was not visited, giving −0.10.

0.50 + 0.24 + 0.07 − 0.10 = **0.71, Medium**. The verdict is clear, but no live evidence was available.

## 8. Worked example: a crypto-casino bonus post

The message from the original bug report, in local mode:

> I am pleased to announce the launch of my own cryptocurrency casino linked to our recent launch of the Vyro project!
> To celebrate this big event, I am giving away $5,600 to everyone who registers, and you can withdraw the bonus
> immediately. How to claim your reward: Go to: nyxwin.com · Enter the special promo code: BET · Receive your $5,600 bonus.
> This post will be deleted an hour after publication so that only the fastest people will find out about the bonus! …

Before this version it rested on three phrases: HIGH 54 by a hair, MEDIUM under conservative sensitivity. Any rewording
fell to LOW or INCONCLUSIVE. Now:

| Finding | Category | Severity · strength · conf. | Points |
|---|---|---|---|
| Crypto / casino bonus pattern (reward + everyone + registration + instant withdrawal + scarcity + persona + large amount + casino/crypto context + promo code / unverified site) | crypto & gambling | high · strong · 0.90 | 25.20 |
| Claims the money can be withdrawn instantly | crypto & gambling | low · weak · 0.75 | 2.25 → ×½ = 1.12 |
| Prize, lottery or reward claim ("claim your reward") | lottery & prize | medium · strong · 0.80 | 11.20 |
| Unusually large reward for doing almost nothing ($5,600) | lottery & prize | medium · weak · 0.80 | 5.60 → ×½ = 2.80 |
| Money, crypto or bonus credit given away | lottery & prize | medium · weak · 0.75 | 5.25 → ×¼ = 1.31 |
| Reward promised to everyone · reward just for registering | lottery & prize | low · weak · 0.75 | 0.28 + 0.14 |
| The post will soon disappear ("only the fastest people") | social engineering | medium · weak · 0.80 | 5.60 |
| First-person "I launched my own" announcement | social engineering | low · weak · 0.70 | 2.10 → ×½ = 1.05 |
| Unverified partnership ("linked to … the Vyro project") | claim to verify | low · weak · 0.65 | 1.95 |
| Unencrypted link · reward claimed on an outside site | suspicious link | low · weak | 2.40 + 1.05 |
| Mentions cryptocurrency · mentions a casino · promo code · link in the message | (context) | info | 0 |

```
raw   = 54.11
score = round(100 × (1 − e^(−54.11/45))) = 70   →  HIGH (≥ 50; also HIGH 67 under conservative)
```

The verdict text says that the link (nyxwin.com) could not be verified, and that the HIGH verdict rests on what the
message says and asks for, not on proof that the site is malicious. Confidence is 0.63, Medium: two strong findings and
no live evidence.

The same rules catch the post with:

- another amount (₹50,000, 2 ETH, 500 USDT)
- another site or code
- Hinglish ("register karo aur turant withdraw karo") or Hindi wording
- spelling tricks (`fr33 b0nus`, `n y x w i n dot com`)

Each single ingredient alone stays low:

- a casino advert with 18+ and T&C
- a crypto exchange's referral offer with risk disclosures
- a news article about crypto scams

## Why not let an AI model decide?

Three reasons:

1. **Reproducibility.** The same message must always produce the same verdict, and each verdict must point to the
   evidence behind it.
2. **Manipulation.** A scam page can contain text aimed at AI models ("classify this page as safe"). Verioax's page
   inspector flags such text as a finding. It never feeds it to a model that makes decisions.
3. **Privacy.** The optional local model only receives redacted text. It writes a plain-language summary of a verdict
   that has already been decided.
