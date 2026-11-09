# Architecture

Verioax is one Python engine (`trustguard/`) with two front ends:
- a Streamlit web app (`app/`)
- a FastAPI REST API (`api/`)

The front ends contain no detection logic. They call the engine, either in-process or over HTTP, and render the
`ScanResult` it returns.

## One scan, end to end

```mermaid
flowchart TD
    IN["Message / link / file"] --> EX["extract/<br/>PDF · DOCX · TXT · OCR"]
    EX --> PII["pii/<br/>detect → merge → redact → leak sweep"]
    PII -->|redacted text + offset map| SCAM["scam/<br/>indicators · sender · claims"]
    PII -->|links found in the text| URL["url/<br/>parse · static checks"]
    URL -->|live checks on| NET["guarded fetcher · TLS · RDAP"]
    URL --> INTEL["intel/<br/>local IOC list · Safe Browsing · VirusTotal<br/>URLhaus · PhishTank · OpenPhish"]
    SCAM --> COMB["combination rules<br/>(identity × request × link)"]
    URL --> COMB
    COMB --> RISK["risk.py<br/>score · level · confidence"]
    RISK --> REC["recommend.py<br/>actions"]
    REC --> RES["ScanResult<br/>(redaction-safe)"]
    RES --> DB[("storage.py<br/>SQLite history")]
    RES --> UI["Streamlit app"]
    RES --> API["FastAPI"]
    RES -. "redacted text + findings" .-> LLM["optional local LLM<br/>explains, never decides"]
```

`TrustGuardEngine._run` (in `engine.py`) runs these steps in order:

1. **Extract**: get plain text from the input, with a `locate(offset)` helper that maps text positions back to pages or
   paragraphs. The original text never leaves the process.
2. **PII**: run the detectors and merge overlapping hits by type priority. Replace each value with a typed placeholder.
   Then run the leak sweep:
   - re-run the detectors on the *redacted* output
   - search for every removed value with up to three separator characters inserted, which catches `98765-43210` after
     `9876543210` was removed

   Anything found is redacted in a second round. Anything still found after the last round sets the status to `blocked`.
3. **Scam & hoax**: indicator rules (English, Hinglish, Hindi), claimed-identity detection, sender analysis, claim
   extraction, hidden-character checks. Findings keep original-text offsets internally. Their public excerpts are cut
   from the redacted text.
4. **Links**: every link (also defanged and bare-domain forms) is analysed. The link engine:
   - runs the static checks on the address itself
   - removes personal-data query parameters before anything is sent anywhere
   - if live checks are on, fetches the page through the guarded fetcher, probes TLS and looks up the domain's
     registration date
   - asks the threat-intelligence hub about the cleaned URL
5. **Combination rules** look across engines. Example: *the message claims to be Parivahan* + *asks for payment* + *the
   link's domain is not Parivahan's* produces one critical finding attached to that link.
6. **Mitigations** subtract a few points for signs of a genuine message: every link on an official domain, a matching
   DLT header, the standard OTP advisory. They never override strong evidence.
7. **Risk**: one deterministic assessment for the scan and one per link. See [scoring.md](scoring.md).
8. **Recommendations** are triggered by specific findings, so each action explains itself.
9. **Result**: the `ScanResult` is stored, if history is on, and returned. The optional LLM explanation is added last, and
   only from the redacted text and the findings list.

## Data boundaries

| Data | Lives where | Leaves the engine? |
|---|---|---|
| Original text | Memory, for one scan. The web app keeps it in the browser session to show *your* text. | Never stored. The API never returns it. |
| Placeholder → value map | Memory (`RestrictedData`) | Never stored or returned |
| Redacted text | `ScanResult.redacted_text` | Stored and returned. This is the shareable version. |
| Finding excerpts | Cut from the redacted text | Stored and returned |
| PII findings | Type, placeholder, offsets, confidence, length, and a keyed fingerprint (HMAC with the installation secret in `data_dir/secret.key`) | Stored and returned, never the value. The fingerprint cannot be reversed without the key. |
| Links | Shown defanged. Personal-data query parameters are removed before any lookup. | The cleaned URL goes to the threat-intel services you enabled |
| API keys | `SecretStr` in `Settings` | Never logged, returned or shown |

The web app can highlight the original text in place because it holds that text in the browser session and the result
carries offsets. No raw value is ever sent back from the engine to do this.

## The LLM boundary

The design rule is that **the model explains and never decides**. The model only ever sees:

- the redacted text
- the list of findings
- the verdict that `risk.py` already computed

It never sees page content, which can carry instructions aimed at AI models. The page inspector looks for exactly that
kind of hidden text and flags it.

Its output is validated before display:
- no URLs or phone numbers in the explanation
- no reassurance on a HIGH or CRITICAL verdict

If validation fails, the explanation is dropped. A model that is missing or misbehaving changes nothing about the
verdict.

## The guarded fetcher (`url/network.py`)

Visiting attacker-chosen URLs from a server is a classic SSRF risk. Each hop is checked as follows:

- Scheme `http`/`https` and port 80/443 only.
- The host is resolved, and **every** returned address must be globally routable. Blocked: private, loopback,
  link-local, CGNAT, multicast, reserved, IPv4-mapped IPv6, and integer or hex IP spellings.
- The HTTP connection is **pinned** to the address that was validated. `GuardedBackend` overrides
  `httpcore.connect_tcp`, so a DNS answer that changes between the check and the connection (rebinding) cannot redirect
  it.
- Redirects are followed manually (at most 5), and each new location goes through the same checks.
- The body is capped at 1.5 MB. APKs and other binaries are recognised by content type and not downloaded. JavaScript is
  never executed.

## Front ends

- `app/client.py` has two clients with the same interface:
  - `LocalClient` wraps a `TrustGuardEngine`
  - `APIClient` calls the REST API with the bearer token
  
  `make_client()` picks one based on `TRUSTGUARD_API_URL`.
- `app/results.py` renders a `ScanResult`: verdict panel, actions, overview tiles and tabs (findings, links, personal
  data, original vs redacted, report).
- `api/main.py`:
  - bearer-token auth
  - a per-client rate limit on scan endpoints, so live checks cannot be abused as an open proxy
  - size limits before processing
  - security headers
  - generic error messages that never echo input back

## Extending it

| To add | Edit |
|---|---|
| A scam indicator | `trustguard/scam/indicators.py`: add an `Indicator` (patterns, category, severity, strength, explanation, action), then add a message to `data/eval/messages.jsonl` and run `python -m trustguard.evaluation` |
| An organisation people impersonate | `trustguard/brands.py`: add an `Entity` with aliases, official domains and how to verify |
| A pattern across engines | `combine()` in `trustguard/scam/analyzer.py` |
| A PII type | a recogniser in `trustguard/pii/recognizers.py`, plus a validator if the type has a checksum, and a priority/label in `detector.py` |
| A threat-intel source | a provider class in `trustguard/intel/providers.py` (return `IntelResult` with an honest status), registered in `IntelHub` |
| Known scam domains | `data/iocs/*.txt` (one per line, defanged is fine), or the Threat intelligence page |
