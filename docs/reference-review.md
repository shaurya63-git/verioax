# Reference project review

Verioax's PII workflow and UI were inspired by a reference project supplied at the start of this work: the *Cadence
PII pipeline*, a case-study submission for document PII detection and redaction. This page has three parts:

- what the reference does
- which of its ideas Verioax adopted
- what Verioax does differently

## What the reference does

The reference is a Python package plus a single-page Streamlit app for **documents**: PDF, PPTX, DOCX and images. Its
pipeline:

1. **Extract** text blocks with layout and word boxes. Scanned pages get OCR, including an optional second OCR reading,
   and low-confidence blocks are flagged.
2. **Detect** PII with patterns, labelled-field rules, name rules and optional spaCy NER, filtered by a minimum
   confidence.
3. **Redact** with typed, document-consistent placeholders (`[PERSON_3]`). OCR variants of one value share a placeholder.
   The placeholder → value map is returned separately, as the only structure holding raw values.
4. **Leak sweep.** The redacted output is re-scanned with the detectors and searched for every removed value. Anything
   found is redacted in a second pass, and anything still found marks the file `blocked`. Optionally, unreadable blocks
   are masked as `[UNREADABLE]` (fail closed).
5. **Report** a status (`clean`, `needs review` or `blocked`) with reasons, totals and a review queue of low-confidence
   findings.

Its UI layout:

- **Sidebar:** the input (sample or upload, page range), followed by *policy* controls: fail-closed masking, minimum
  confidence, second OCR reading, spaCy NER, leak-sweep rounds.
- **Main area:** a status banner, a row of five metrics (findings, distinct values, blocks changed, caught by leak sweep,
  review queue), then five tabs: *Document view*, *Original vs redacted*, *Exposure report*, *Extraction*, *Evidence*.
  The Evidence tab shows evaluation against hand-labelled gold sets.

## Ideas Verioax adopted

| Reference idea | How Verioax implements it |
|---|---|
| Typed, consistent placeholders | `[TYPE_001]`, zero-padded and stable within a scan. Phone numbers are compared by digits, so `+91 98765 43210` and `9876543210` share one placeholder. A bare first or last name reuses the placeholder of the detected person. |
| Raw values only in a separate map | `RestrictedPII` / `RestrictedData` exist only in memory for the current scan. Verioax goes further: the map is never written to disk, never returned by the API and never offered as a download. |
| Leak sweep that tries to break the output | Detectors re-run on the redacted text, plus a tolerant search for every removed value with up to 3 separator characters inserted. 0–3 rounds (default 2). Anything left after the last round sets the status to `blocked`. |
| `clean` / `needs review` / `blocked` with reasons | The same three states, shown on the *Personal data* tab and in every report |
| Review queue below a confidence threshold | `pii_review_threshold` (default 0.65), listed under *For review* |
| Policy controls | The **Settings** page: thresholds, sweep rounds, NER, network and privacy switches. They are persisted, and every result records the settings hash. |
| Status banner + metric row + tabs | Verdict panel with a risk scale + six overview tiles + tabs |
| *Original vs redacted* tab | Kept, and extended: scam warnings stay highlighted on the redacted side, which is the copy users can share |
| *Exposure report* | *Personal data* tab and a privacy exposure score |
| *Evidence* tab with evaluation | **Reports & analytics → Detection quality**: runs the labelled regression set and shows every miss, with the same honesty note about what the numbers do and do not show |

## What is different, and why

- **Messages first.** The reference is built around document layout (blocks, word boxes, OCR confidence per block).
  Verioax's main inputs are SMS, WhatsApp messages, emails and links. Documents are supported through text extraction
  and OCR, but there is no word-box image redaction.
- **Identifiers checked by checksum.** Aadhaar (Verhoeff), PAN (holder type), GSTIN (base-36 checksum), cards (Luhn),
  IBAN, vehicle registrations including BH series, and UPI IDs. Failed checksums lower confidence and send the finding to
  review.
- **A second, separate engine.** The scam, hoax and link-integrity module is new. It reads the redaction output (offset
  map and redacted text) for everything it shows or stores. It never changes what the PII engine redacts.
- **No fail-closed `[UNREADABLE]` masking.** Messages are mostly typed text. OCR'd inputs carry a warning instead.
- **Keyed fingerprints** instead of plain value hashes, because a hash of a phone number can be brute-forced.
- **A multi-page app.** It has a dashboard, history, threat intelligence, analytics and settings, plus a REST API, a dark
  theme and self-hosted fonts.

## Originality

**No source code was copied.** The reference repository has no licence file, which means all rights are reserved by
default. Verioax re-implements the ideas above from scratch, with its own data structures, detectors, validators,
tests and UI code. The reference is credited in the README.
