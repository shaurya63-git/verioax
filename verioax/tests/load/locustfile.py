"""Locust scenarios for the Verioax API - see docs/load-testing.md.

Run them against a LOCAL API in offline mode (no threat-intelligence lookups, no live link visits), never against third-
party services or real phishing sites. ``python tests/load/run_load.py`` starts such an API and runs every scenario at
10/25/50/100 users; by hand:

    locust -f tests/load/locustfile.py --host http://127.0.0.1:8000 MessageScanUser

Set VERIOAX_LOAD_TOKEN to the API token (TRUSTGUARD_API_TOKEN of the server). Every input below is synthetic.
"""
from __future__ import annotations

import os
import random
from pathlib import Path

from locust import HttpUser, between, constant, task

TOKEN = os.environ.get("VERIOAX_LOAD_TOKEN", "")
ABUSE = os.environ.get("VERIOAX_LOAD_ABUSE") == "1"          # deliberate burst: 429s are the expected, correct answer
NO_WAIT = os.environ.get("VERIOAX_LOAD_NO_WAIT") == "1"      # saturation run: every user sends its next scan at once
SAMPLES = Path(__file__).resolve().parents[2] / "samples"

MESSAGES = [
    "Your vehicle MH12AB1234 has a pending e-challan of Rs 500. Pay now to avoid licence suspension: https://echallan-pay.vip/pay",
    "I am giving away $5,000 to everyone who registers on spinwin-casino.io - withdraw instantly! Promo code WIN. This post will be "
    "deleted in an hour, only the fastest get the bonus!",
    "Dear customer, your SBI account will be blocked today. Update PAN KYC: http://sbi-kyc-update.top/login or call 9876543210.",
    "Congratulations! You won Rs 25 lakh in the KBC lottery. Pay Rs 15,000 processing fee to claim. WhatsApp +91 98765 43210.",
    "This is CBI. A parcel in your name contains drugs. You are under digital arrest - stay on video call and transfer the money "
    "for verification.",
    "Part-time job: earn Rs 5,000/day liking YouTube videos. Pay Rs 999 registration fee on Telegram to start.",
    "Your OTP for login is 482913. Do not share it with anyone. - HDFC Bank",
    "Hi Priya, the team lunch is at 1 pm on Friday at the usual place. See you there!",
    "Rs 2,499.00 debited from A/c XX1234 on 14-11-26 for UPI txn to Swiggy. Not you? Call 1800-1234 (toll free).",
    "Reminder: your electricity bill of Rs 1,240 is due on 20 Nov. Pay on the official app or website.",
    "PIB Fact Check: a viral message claims the government is giving free laptops to all students. This claim is FAKE.",
    "Airdrop LIVE: connect your wallet at claim-eth-airdrop.xyz and enter your seed phrase to receive 2 ETH.",
]
URLS = [
    "http://sbi-kyc-update.top/login/verify",
    "https://echallan-parivahan.gov.in.pay-fine.vip/challan",
    "https://www.wikipedia.org/",
    "https://onlinesbi.sbi/",
    "hxxps://claim-eth-airdrop[.]xyz/connect",
    "https://bit.ly/3xYzAbC",
    "https://amaz0n-reward.shop/gift?ref=whatsapp",
    "https://www.irctc.co.in/nget/train-search",
]
_PDF = SAMPLES / "kyc_phishing_email.pdf"
FILES = [("notice.txt", "\n".join(random.sample(MESSAGES, 4)).encode(), "text/plain")]
if _PDF.is_file():
    FILES.append(("kyc_phishing_email.pdf", _PDF.read_bytes(), "application/pdf"))


class _ScanUser(HttpUser):
    abstract = True
    wait_time = constant(0) if (ABUSE or NO_WAIT) else between(0.5, 1.5)   # people pause between scans; these runs don't

    def on_start(self):
        self.owner = random.randint(1, 200)                      # spread the scans over many accounts
        self.headers = {"X-Verioax-Owner": str(self.owner)}
        if TOKEN:
            self.headers["Authorization"] = f"Bearer {TOKEN}"

    def _check(self, r):
        if r.status_code == 200:
            r.success()
        elif r.status_code == 429:
            # in the abuse run a 429 is the correct answer; it is still listed separately so the report can count them
            r.failure("HTTP 429 rate limited (expected in the burst run)" if ABUSE else "HTTP 429 rate limited")
        else:
            r.failure(f"HTTP {r.status_code}")


class MessageScanUser(_ScanUser):
    @task
    def scan_message(self):
        with self.client.post("/v1/scan/message", json={"text": random.choice(MESSAGES)}, headers=self.headers,
                              name="/v1/scan/message", catch_response=True) as r:
            self._check(r)


class URLScanUser(_ScanUser):
    @task
    def scan_url(self):
        with self.client.post("/v1/scan/url", json={"url": random.choice(URLS)}, headers=self.headers,
                              name="/v1/scan/url", catch_response=True) as r:
            self._check(r)


class FileScanUser(_ScanUser):
    @task
    def scan_file(self):
        name, blob, mime = random.choice(FILES)
        with self.client.post("/v1/scan/file", files={"file": (name, blob, mime)}, data={"mode": "full"}, headers=self.headers,
                              name="/v1/scan/file", catch_response=True) as r:
            self._check(r)
