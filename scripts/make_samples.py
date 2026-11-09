"""Generate the sample files in ``samples/`` used by the File scanner's "Try a sample file" option.

    python scripts/make_samples.py

Every file is synthetic and says so in its first line. Names, numbers and addresses are made up (example.com addresses,
placeholder phone numbers); the links use lookalike domains of the kind described in public advisories.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "samples"
BANNER = "Verioax sample file - synthetic content for testing. All names and numbers are made up."

KYC_EMAIL = [
    "From: SBI Alerts <alerts@sbi-secure-kyc.com>",
    "To: priya.sharma@example.com",
    "Subject: Urgent: your YONO account will be blocked today",
    "",
    "Dear Priya Sharma,",
    "",
    "Your KYC has expired and your SBI account will be suspended within 24 hours. To avoid blocking, update your PAN",
    "and Aadhaar details immediately using the secure link below and enter the OTP sent to your registered mobile.",
    "",
    "Update now: https://sbi-secure-kyc.com/yono/update",
    "",
    "Account holder: Priya Sharma",
    "Account number: 123456789012   IFSC: SBIN0001234",
    "PAN: ABCPS1234K",
    "Registered mobile: +91 98765 43210",
    "",
    "Regards,",
    "KYC Department",
]

FORWARDS = [
    ("Forwarded many times - family group, 9:14 am",
     "Big news! Lok Adalat on 13 December will waive 50% of all traffic challans. Forward to all your friends and family before it is too late."),
    ("Forwarded - from +91 98765 43210, 11:02 am",
     "Dear Ravi Kumar, your vehicle MH12AB1234 has a pending e-challan of Rs 590. Pay immediately to avoid licence suspension and "
     "court proceedings: https://echallan-pay.vip/pay"),
    ("SMS from VM-HDFCBK-T, 6:40 pm",
     "482913 is your OTP for login to NetBanking. Do not share it with anyone. -HDFC Bank"),
]

SMS_SCREENSHOT = [
    "+91 70123 45678",
    "Today 10:24 AM",
    "",
    "RTO NOTICE: Your vehicle has an unpaid",
    "traffic challan of Rs 500. Pay today to avoid",
    "licence suspension and court summons.",
    "Pay now: http://parivahan-echallan.top/pay",
]


def make_pdf(path: Path) -> None:
    from reportlab import rl_config
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    rl_config.useA85 = 0      # raw compressed streams: the PDF is binary, so Git never rewrites its line endings on Windows

    c = canvas.Canvas(str(path), pagesize=A4, pageCompression=1)
    _, h = A4
    c.setTitle("Verioax sample - KYC phishing email")
    c.setFont("Helvetica-Oblique", 8.5)
    c.drawString(50, h - 40, BANNER)
    c.setFont("Helvetica", 10.5)
    y = h - 75
    for line in KYC_EMAIL:
        c.drawString(50, y, line)
        y -= 16
    c.showPage()
    c.save()


def make_docx(path: Path) -> None:
    from docx import Document

    doc = Document()
    doc.core_properties.title = "Verioax sample - forwarded messages"
    doc.add_paragraph(BANNER).italic = True
    doc.add_heading("Messages to check", level=1)
    for meta, text in FORWARDS:
        doc.add_paragraph(meta).runs[0].bold = True
        doc.add_paragraph(text)
    doc.save(str(path))


def make_png(path: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont

    def font(size: int, bold: bool = False):
        name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
        for base in ("/usr/share/fonts/truetype/dejavu", "/Library/Fonts", "C:/Windows/Fonts"):
            try:
                return ImageFont.truetype(f"{base}/{name}", size)
            except OSError:
                continue
        return ImageFont.load_default()

    img = Image.new("RGB", (900, 560), "white")
    d = ImageDraw.Draw(img)
    d.text((30, 18), BANNER, fill=(110, 110, 110), font=font(15))
    d.rounded_rectangle((30, 60, 870, 530), radius=24, fill=(236, 239, 244))
    y = 85
    for i, line in enumerate(SMS_SCREENSHOT):
        d.text((60, y), line, fill=(20, 20, 20), font=font(30 if i == 0 else 27, bold=i == 0))
        y += 50 if i == 0 else 46
    img.save(path, optimize=True)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    make_pdf(OUT / "kyc_phishing_email.pdf")
    make_docx(OUT / "forwarded_messages.docx")
    make_png(OUT / "challan_sms_screenshot.png")
    for p in sorted(OUT.iterdir()):
        print(f"{p.relative_to(ROOT)}  {p.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
