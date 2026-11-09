"""Sample messages for demonstration mode.

They are synthetic (modelled on public advisories about e-challan, KYC, prize, task and 'digital arrest' scams) and
contain no real personal data. When they are loaded from the dashboard they are analysed by the real engine and stored
with ``demo=True``, so the UI can label them as sample data and Settings can remove them in one click.
"""
from __future__ import annotations

SAMPLES: list[dict] = [
    {"label": "Fake e-challan", "sender": "+91 98765 43210",
     "text": "Dear Ravi Kumar, your vehicle MH12AB1234 has a pending e-challan of Rs 590. Pay immediately to avoid licence suspension "
             "and court proceedings: https://echallan-pay.vip/pay"},
    {"label": "Bank KYC phishing", "sender": "",
     "text": "Dear customer, your SBI YONO account will be blocked today. Update your PAN immediately: http://sbi-kyc-update.com/yono"},
    {"label": "Prize with a fee", "sender": "+92 300 1234567",
     "text": "Congratulations! You have won Rs 25,00,000 in KBC lucky draw. To claim, pay processing fee Rs 4,999 to kbc.winner@ybl "
             "and send the screenshot on WhatsApp 9876501234."},
    {"label": "Digital arrest", "sender": "+855 12 345 678",
     "text": "This is CBI. A parcel in your name contains drugs. You are under digital arrest. Stay on the video call and do not tell "
             "anyone. Transfer Rs 2,00,000 for verification."},
    {"label": "Hoax forward", "sender": "",
     "text": "Big news! Lok Adalat on 13 December will waive 50% of all traffic challans. Forward to all your friends."},
    {"label": "Genuine OTP", "sender": "VM-HDFCBK-T",
     "text": "482913 is your OTP for login to NetBanking. Do not share it with anyone. -HDFC Bank"},
    {"label": "Official e-challan", "sender": "VM-PARIVA-G",
     "text": "Challan for vehicle MH12AB1234 issued on 02-11-2026. Check details and pay at https://echallan.parivahan.gov.in"},
]

SAMPLE_URLS = ["https://parivahan-gov.in/pay", "https://echallan.parivahan.gov.in/", "https://bit.ly/3echln"]
