# Evaluation

Verioax's detection is rule-based, so it can only be judged on labelled examples. This page explains the two sets, how
they are used, what the numbers mean and what they don't.

```bash
python -m trustguard.evaluation                        # development set; exit code 1 if detection or false alarms regress
python -m trustguard.evaluation --set holdout          # the held-out set (see the protocol below before running it)
python -m trustguard.evaluation --set all --json out.json
```

## The two sets

| Set | File | Rows | Purpose |
|---|---|---|---|
| Development | `data/eval/messages.jsonl` | 162 | Rules were written and tuned against it. A regression gate in CI and the tests. |
| Held-out | `data/eval/holdout.jsonl` | 133 | Frozen **before** any detection change in this version (commit `83c034e`). Never used for tuning. |

Each row has:

- a label: `threat`, `hoax`, `suspicious`, `benign` or `neutral`
- a category: `crypto_casino`, `e_challan`, `bank_genuine`, `factcheck`, ...
- the message text, or a URL for link rows

**Freezing.** The held-out file's SHA-256 is pinned in `tests/test_eval.py`
(`118719f052a01102f16ef5b5db050a60278605be7a05094c44e1235ded128b76`). Editing it fails the tests.

**Protocol.** During development, only aggregate held-out numbers were looked at, never individual misses. Rules were
changed only in response to development-set rows and new development examples. The full held-out report (per-category
results, missed rows) was produced **once**, at the end. No rule was changed afterwards.

**What the held-out set covers** (81 threats, 8 hoaxes, 40 genuine, 4 ambiguous):

- **Threats:** crypto casino / betting bonus, crypto giveaway, wallet drainer, UPI collect requests, OTP theft, fake
  customer care, e-challan, KYC / bank phishing, digital arrest, job, investment, government scheme, delivery, lottery,
  advance fee, and fake APK links.
- **Genuine:** transactional bank and UPI messages, government notices, real e-challan notices, cashback and
  telecom promotions, lawful casino and crypto-exchange adverts with disclosures, investment education, and awareness
  and fact-check messages that quote scams.
- **Languages:** English, Hindi and Hinglish, plus evasion spellings (`fr33`, spaced letters, `dot com`).

## Metrics

Two operating points are reported, because people use the verdict in two ways:

- **Alert** (MEDIUM or worse = flagged). Used for "should I be careful?".
- **Likely scam** (HIGH or worse = flagged). Used for "this is a scam".

For each: precision, recall, F1 and false-positive rate.

- **Alert:** positives are threat, hoax and suspicious rows.
- **Likely scam:** positives are threat rows only.

Negatives are always the genuine (`benign`) and `neutral` rows. A `neutral` row is an unknown but legitimate site.

Also reported:

- **Confusion matrix:** label × verdict level.
- **Per-category rate:** the share of a category's rows that got the expected verdict:
  - threats need HIGH or worse
  - hoaxes need MEDIUM or worse, with a hoax finding
  - suspicious rows need anything but LOW
  - genuine rows need LOW
  - neutral rows (unknown legitimate sites) need LOW or INCONCLUSIVE
- **Genuine false alarms, three ways:**
  - strict: anything except LOW
  - alarm: MEDIUM or worse
  - high: HIGH or worse
- **Scam-type accuracy** per category, and precision per predicted scam type.

## Results

Both runs are offline: no live link checks and no threat intelligence, so a link only counts as checked from its own
text. "Before" is the code this version started from (commit `2efd2e9`), run on the same frozen set.

### Held-out set (133 rows, never tuned against)

| Measure | Before | After |
|---|---|---|
| Scams rated HIGH or CRITICAL (likely-scam recall) | 42 / 81 = **0.519** | 66 / 81 = **0.815** |
| Likely-scam precision | 1.000 | 1.000 |
| Likely-scam F1 | 0.683 | **0.898** |
| Likely-scam false-positive rate (genuine rated HIGH+) | 0.000 | 0.000 |
| Alert recall (threats, hoaxes, suspicious rated MEDIUM+) | 63 / 91 = 0.692 | 84 / 91 = **0.923** |
| Alert precision | 0.969 | **1.000** |
| Alert F1 | 0.808 | **0.960** |
| Alert false-positive rate (genuine and neutral rated MEDIUM+) | 0.048 | **0.000** |
| Genuine messages not rated LOW (strict) | 3 / 40 = 0.075 | 1 / 40 = 0.025 (one INCONCLUSIVE) |
| Hoaxes flagged with a hoax finding | 8 / 8 | 8 / 8 |

The 95% Wilson interval for likely-scam recall is 0.41–0.62 before and 0.72–0.88 after. These intervals describe this
set only (see the limitations below); no claim of statistical significance on real-world traffic is made.

Confusion matrix (rows = label, columns = verdict LOW / INCONCLUSIVE / MEDIUM / HIGH / CRITICAL):

| Label | Before | After |
|---|---|---|
| threat (81) | 16 / 10 / 13 / 24 / 18 | 4 / 1 / 10 / 45 / 21 |
| hoax (8) | 0 / 0 / 8 / 0 / 0 | 0 / 0 / 8 / 0 / 0 |
| suspicious (2) | 0 / 2 / 0 / 0 / 0 | 0 / 2 / 0 / 0 / 0 |
| benign (40) | 37 / 1 / 2 / 0 / 0 | 39 / 1 / 0 / 0 / 0 |
| neutral (2) | 0 / 2 / 0 / 0 / 0 | 0 / 2 / 0 / 0 / 0 |

Per category (share of rows with the expected verdict):

| Category | Rows | Before | After |
|---|---|---|---|
| crypto casino / betting bonus | 10 | 0.20 | **0.90** |
| crypto giveaway | 3 | 0.00 | **1.00** |
| crypto wallet drainer | 6 | 0.17 | **0.83** |
| UPI payment fraud | 4 | 0.25 | **0.75** |
| advance fee | 4 | 0.25 | 0.50 |
| bank phishing | 5 | 0.60 | 0.80 |
| KYC phishing | 3 | 0.67 | 0.67 |
| digital arrest | 3 | 0.67 | **1.00** |
| investment | 6 | 0.67 | **1.00** |
| fake customer support | 3 | 0.67 | **1.00** |
| giveaway | 7 | 0.86 | **1.00** |
| job | 4 | 0.50 | 0.75 |
| e-challan | 4 | 0.75 | 0.75 |
| OTP theft | 4 | 0.50 | 0.50 |
| fake APK links | 3 | 0.33 | 0.33 |
| lottery | 2 | 0.00 | 0.00 |
| delivery, government scheme, refund | 3 + 4 + 3 | 1.00 | 1.00 |
| awareness (genuine) | 4 | 0.75 | **1.00** |
| genuine cashback | 3 | 0.67 | **1.00** |
| genuine bank, government, promotions, crypto, casino, e-challan, personal, fact-check, news | 31 | 1.00 | 1.00 |
| investment education (genuine) | 2 | 0.50 | 0.50 (one INCONCLUSIVE: its only link could not be verified) |

Scam-type accuracy on the detected held-out threats is 0.78–1.00 for most categories. The weak spots: delivery (1 of 3
named correctly), KYC phishing (1 of 2). Two threats were named only "impersonation".

**What the held-out set still misses** (15 of 81 threats below HIGH). These are reported, not fixed: fixing them would
mean tuning against this set.

- OTP-theft messages with no link and no number (two rows: LOW).
- A UPI "collect request" story and a job offer written without the usual lure words (LOW).
- Lottery and advance-fee messages that reach MEDIUM 25–47 but not HIGH (four rows).
- Fake APK links (two rows: MEDIUM 41).
- Bank / KYC / e-challan messages just under the threshold (three rows: MEDIUM 41–49).
- One crypto-casino post whose only signal is an unverifiable link (INCONCLUSIVE).

### Development set (162 rows, rules tuned against it)

All 70 threats HIGH or CRITICAL, all 17 hoaxes flagged, no genuine message rated MEDIUM or worse (one genuine news
message with an unverifiable link is INCONCLUSIVE). The scam type is right on 69 of 70 threats. This is a regression
check, not a benchmark.

### Run history

The full held-out report was produced at the end of development. One later change was made in response to new
development examples: police and researcher warnings about scams are now recognised as warnings. The held-out set was
run again on the final code, with **identical** results; the change did not move a single held-out verdict.

### The exact message from the bug report

| Version | Balanced | Conservative |
|---|---|---|
| Before (`2efd2e9`) | HIGH 54: three phrases, borderline | MEDIUM 52 |
| The version before that | MEDIUM 30 | - |
| Before: reworded / "nyxwin dot com" / Hinglish | INCONCLUSIVE 14 / LOW 15 / INCONCLUSIVE 10 | - |
| **After** | **HIGH 70**, type "crypto casino / betting bonus scam" | **HIGH 67** |
| After: other amounts, sites, Hinglish, spelling tricks | HIGH 59–63 | - |

It is a permanent regression case (`D001` in the development set, and `tests/test_detection.py`).

## Limitations of the data

- **Both sets were written by the project.** They are synthetic, modelled on public advisories (Cyble, PIB Fact Check,
  I4C / Cyber Dost, RBI and bank warnings, news reports). The held-out set was frozen before tuning and never looked at
  row by row until the end, but the same author wrote the rules and the examples. Real scam messages will contain
  wordings that neither set has. Expect real-world recall to be lower than these numbers.
- **Small categories.** Most categories have 2–10 held-out rows, so one row moves a rate by 10–50 points. Treat the
  per-category numbers as a map of weak spots, not as accuracy figures.
- **Offline only.** With live checks and threat intelligence on, link-based verdicts can only get stronger: a confirmed
  blocklist hit can raise a verdict, and an unreachable link never lowers one. These runs don't measure that.
- **The score is not a probability.** A score of 70 means "HIGH on Verioax's rule scale", not "70% chance of fraud". It
  has not been calibrated against real-world base rates.
