# How TrustGuard scores a scan

TrustGuard reports two separate numbers:

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
| category | one of 15 | e.g. government impersonation, phishing, hoax |

What each strength means:

- **Weak:** common in scams, but also in honest messages. Examples: urgency words, "pay now", a `.vip` domain.
- **Strong:** rarely legitimate. Examples: a lookalike of a bank's domain, or a government body texting from a personal
  mobile number.
- **Confirmed:** direct evidence. Examples: a match on a threat-intelligence blocklist or the local indicator list, or the
  live page asking for card number and CVV.

`info` findings (a link was found, an amount was mentioned) give context and add no points.

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

## Why not let an AI model decide?

Three reasons:

1. **Reproducibility.** The same message must always produce the same verdict, and each verdict must point to the
   evidence behind it.
2. **Manipulation.** A scam page can contain text aimed at AI models ("classify this page as safe"). TrustGuard's page
   inspector flags such text as a finding. It never feeds it to a model that makes decisions.
3. **Privacy.** The optional local model only receives redacted text. It writes a plain-language summary of a verdict
   that has already been decided.
