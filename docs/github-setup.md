# Publishing Verioax on GitHub

These steps take the project folder to a public GitHub repository with passing CI. Replace `<your-username>` with your
GitHub username throughout.

## 1. One-time setup

1. Create a GitHub account if you don't have one.
2. Install Git (Windows: <https://git-scm.com/download/win>, macOS: `xcode-select --install`, Linux:
   `sudo apt install git`).
3. Tell Git who you are. This is recorded in every commit:

   ```bash
   git config --global user.name  "Your Name"
   git config --global user.email "you@example.com"
   ```

   To keep your real email private, use the `<id>+<username>@users.noreply.github.com` address shown under GitHub →
   Settings → Emails.
4. Install the GitHub CLI (optional, but it makes step 4 one command): <https://cli.github.com>. Then run
   `gh auth login`.

## 2. Check the folder before the first commit

```bash
cd trustguard-ai
ls -a            # you should see .gitignore, .env.example, README.md ... and NO .env
```

- **Never commit `.env`.** It holds your API keys. `.gitignore` already excludes it, along with `data/runtime/` (your
  scan history, cache and `secret.key`), virtual environments and caches.
- Run the checks once, so the first commit is a green one:

  ```bash
  pip install -r requirements.txt
  ruff check . && pytest -q && python -m trustguard.evaluation
  ```

## 3. Create the local repository

```bash
git init -b main
git add .
git status                       # read the list: no .env, no data/runtime, no .venv
git commit -m "Verioax: PII redaction + explainable scam, hoax and link analysis"
```

## 4. Create the GitHub repository and push

**Option A: GitHub CLI (fastest)**

```bash
gh repo create trustguard-ai --public --source=. --remote=origin --push \
  --description "Redacts personal data, then explains whether a message, link or document is a scam - built for Indian e-challan, KYC and UPI fraud."
```

**Option B: the website**

1. Go to <https://github.com/new>.
2. Name the repository `trustguard-ai`, set it to Public, and **don't** add a README, .gitignore or licence. The project
   already has them.
3. Connect your local repository and push:

   ```bash
   git remote add origin https://github.com/<your-username>/trustguard-ai.git
   git push -u origin main
   ```

   When Git asks for a password, paste a **personal access token** (GitHub → Settings → Developer settings → Personal
   access tokens → Fine-grained, with *Contents: Read and write* on this repository). Your account password won't work.

## 5. Make the repository page look finished

- **About** (gear icon on the repository page):
  - Add the description.
  - Add these topics: `cybersecurity`, `phishing-detection`, `scam-detection`, `pii-redaction`, `privacy`,
    `threat-intelligence`, `streamlit`, `fastapi`, `python`, `india`.
- **Actions** tab: the CI workflow (`.github/workflows/ci.yml`) runs lint, tests and the regression set on Python 3.10,
  3.12 and 3.13 for every push. Wait for the green tick. Then add the badge at the top of the README:

  ```markdown
  [![CI](https://github.com/<your-username>/trustguard-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-username>/trustguard-ai/actions/workflows/ci.yml)
  ```
- **Pin** the repository on your profile (Profile → Customize your pins).
- **Release:**
  ```bash
  git tag -a v0.1.0 -m "First public version"
  git push origin v0.1.0
  ```
  Then click *Create release from tag* on GitHub.
- Optional, in **Settings**:
  - Code security: enable *Dependabot alerts* and *Secret scanning*.
  - Branches: protect `main` so CI must pass before merging.

## 6. Day-to-day workflow

```bash
git switch -c feature/new-indicator     # work on a branch
# ...edit, then:
ruff check . && pytest -q
git add -p                              # review each change before staging
git commit -m "Add courier customs-fee indicator"
git push -u origin feature/new-indicator
gh pr create --fill                     # or open the pull request on the website
```

## If a secret ever gets committed

Deleting the file in a new commit does **not** remove it from history, and public repositories are scanned for keys
within minutes. Do this:

1. **Revoke or rotate the key at the provider first.** Google Cloud console, VirusTotal, abuse.ch and so on.
2. Then put the new key in `.env` only.

## Describing the project (résumé / LinkedIn)

Keep the claims to what the repository shows:

- Built Verioax, a Python security tool that redacts personal data, then explains whether a message, link or
  document is a scam or hoax. It is aimed at Indian e-challan, KYC and UPI fraud. It has a FastAPI backend, a Streamlit
  UI, and 169 automated tests.
- Designed a PII engine with checksum validation for Aadhaar, PAN, GSTIN and cards, typed placeholders, and a leak sweep
  that re-attacks its own output.
- Implemented an SSRF-guarded link inspector: public-IP pinning against DNS rebinding, per-hop redirect validation, size
  caps, no JavaScript. It also inspects pages for credential forms and hidden prompt-injection text, and integrates
  Google Safe Browsing, VirusTotal, URLhaus and PhishTank.
- Built a transparent, deterministic risk model with separate confidence, combination rules and documented guard rails,
  with a labelled regression set run in CI.
