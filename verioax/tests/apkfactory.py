"""Builds small synthetic APKs for the tests: a compiled (binary XML) AndroidManifest.xml, a minimal DEX string table,
optional native libraries, assets and a v1 signature. Nothing here is executable code - the DEX files contain only a
string table, which is all the analyser reads."""
from __future__ import annotations

import io
import struct
import zipfile

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTR_IDS = {"label": 0x01010001, "name": 0x01010003, "permission": 0x01010006, "debuggable": 0x0101000F, "exported": 0x01010010,
            "priority": 0x0101001C, "minSdkVersion": 0x0101020C, "versionCode": 0x0101021B, "versionName": 0x0101021C,
            "targetSdkVersion": 0x01010270}


def _pool(strings: list[str]) -> bytes:
    offsets, data = [], b""
    for s in strings:
        offsets.append(len(data))
        enc = s.encode("utf-16-le")
        data += struct.pack("<H", len(s)) + enc + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    header = 28
    body = b"".join(struct.pack("<I", o) for o in offsets) + data
    strings_start = header + 4 * len(strings)
    return struct.pack("<HHIIIIII", 0x0001, header, header + len(body), len(strings), 0, 0, strings_start, 0) + body


def manifest(package: str, label: str, permissions: list[str], components: list[dict], *, target_sdk: int = 30, min_sdk: int = 21,
             debuggable: bool = False) -> bytes:
    """components: {"kind": "receiver", "name": ".SmsReceiver", "exported": True, "permission": None, "actions": [...], "priority": 999}"""
    # attribute names first, so their indexes line up with the resource map
    attr_names = list(ATTR_IDS)
    strings: list[str] = attr_names + [ANDROID_NS, "android", "manifest", "package", "uses-sdk", "uses-permission", "application", "intent-filter",
                                       "action", "category"]

    def idx(s: str) -> int:
        if s not in strings:
            strings.append(s)
        return strings.index(s)

    events: list[tuple] = []

    def start(tag: str, attrs: list[tuple[str, object, bool]]):
        events.append(("start", tag, attrs))

    def end(tag: str):
        events.append(("end", tag))

    start("manifest", [("package", package, False), ("versionCode", 1, True), ("versionName", "1.0", True)])
    start("uses-sdk", [("minSdkVersion", min_sdk, True), ("targetSdkVersion", target_sdk, True)])
    end("uses-sdk")
    for p in permissions:
        start("uses-permission", [("name", p, True)])
        end("uses-permission")
    start("application", [("label", label, True), ("debuggable", debuggable, True)])
    for c in components:
        attrs = [("name", c["name"], True)]
        if "exported" in c:
            attrs.append(("exported", bool(c["exported"]), True))
        if c.get("permission"):
            attrs.append(("permission", c["permission"], True))
        start(c["kind"], attrs)
        if c.get("actions"):
            start("intent-filter", [("priority", c["priority"], True)] if c.get("priority") else [])
            for a in c["actions"]:
                start("action", [("name", a, True)])
                end("action")
            for cat in c.get("categories", []):
                start("category", [("name", cat, True)])
                end("category")
            end("intent-filter")
        end(c["kind"])
    end("application")
    end("manifest")

    # make sure every string exists before the pool is written
    for ev in events:
        idx(ev[1])
        if ev[0] == "start":
            for name, val, _ in ev[2]:
                idx(name)
                if isinstance(val, str):
                    idx(val)
    ns_i, prefix_i = strings.index(ANDROID_NS), strings.index("android")
    chunks = [_pool(strings)]
    resmap = b"".join(struct.pack("<I", ATTR_IDS[n]) for n in attr_names)
    chunks.append(struct.pack("<HHI", 0x0180, 8, 8 + len(resmap)) + resmap)
    chunks.append(struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, prefix_i, ns_i))
    for ev in events:
        if ev[0] == "start":
            _, tag, attrs = ev
            body = b""
            for name, val, android in attrs:
                if isinstance(val, bool):
                    raw, vtype, data = 0xFFFFFFFF, 0x12, 0xFFFFFFFF if val else 0
                elif isinstance(val, int):
                    raw, vtype, data = 0xFFFFFFFF, 0x10, val
                else:
                    raw, vtype, data = strings.index(val), 0x03, strings.index(val)
                body += struct.pack("<IIIHBBI", ns_i if android else 0xFFFFFFFF, strings.index(name), raw, 8, 0, vtype, data)
            ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, strings.index(tag), 20, 20, len(attrs), 0, 0, 0)
            chunks.append(struct.pack("<HHIII", 0x0102, 16, 16 + len(ext) + len(body), 1, 0xFFFFFFFF) + ext + body)
        else:
            chunks.append(struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, strings.index(ev[1])))
    chunks.append(struct.pack("<HHIIIII", 0x0101, 16, 24, 1, 0xFFFFFFFF, prefix_i, ns_i))
    body = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def dex(strings: list[str]) -> bytes:
    """A DEX file that contains nothing but a string table."""
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    data = b""
    ids = []
    base = 0x70 + 4 * len(strings)
    for s in strings:
        ids.append(base + len(data))
        enc = s.encode("utf-8")
        n = len(s)
        uleb = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            uleb.append(b | (0x80 if n else 0))
            if not n:
                break
        data += bytes(uleb) + enc + b"\x00"
    struct.pack_into("<II", header, 0x38, len(strings), 0x70)
    return bytes(header) + b"".join(struct.pack("<I", i) for i in ids) + data


def build(manifest_bytes: bytes, *, dex_strings: list[str] | None = None, extra: dict[str, bytes] | None = None,
          sign: str | None = "debug") -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest_bytes)
        z.writestr("classes.dex", dex(dex_strings or ["Landroid/app/Activity;", "onCreate"]))
        for name, blob in (extra or {}).items():
            z.writestr(name, blob)
        if sign:
            z.writestr("META-INF/CERT.RSA", _pkcs7(sign))
    return out.getvalue()


def _pkcs7(kind: str) -> bytes:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = {"debug": [x509.NameAttribute(NameOID.COMMON_NAME, "Android Debug"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android")],
             "testkey": [x509.NameAttribute(NameOID.EMAIL_ADDRESS, "android@android.com"), x509.NameAttribute(NameOID.COMMON_NAME, "Android"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android")],
             "release": [x509.NameAttribute(NameOID.COMMON_NAME, "Example Publisher Ltd")]}[kind]
    name = x509.Name(attrs)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650)).sign(key, hashes.SHA256()))
    return pkcs7.PKCS7SignatureBuilder().set_data(b"manifest").add_signer(cert, key, hashes.SHA256()).sign(
        serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])


def sms_stealer() -> bytes:
    """The shape of the 'SBI Rewards' / 'RTO Challan' APKs: a bank name, SMS access, a high-priority SMS receiver and a Telegram bot."""
    m = manifest("com.sbi.rewardz.points", "SBI Rewardz", ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
                                                            "android.permission.INTERNET", "android.permission.SEND_SMS"],
                 [{"kind": "activity", "name": ".MainActivity", "actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]},
                  {"kind": "receiver", "name": ".SmsReceiver", "exported": True, "actions": ["android.provider.Telephony.SMS_RECEIVED"], "priority": 999}])
    return build(m, dex_strings=["Landroid/telephony/SmsManager;", "sendTextMessage", "android.provider.Telephony.SMS_RECEIVED", "getMessageBody",
                                 "https://api.telegram.org/bot7000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage", "setComponentEnabledSetting"],
                 sign="testkey")


def harmless_app() -> bytes:
    m = manifest("org.example.notes", "Simple Notes", ["android.permission.INTERNET"],
                 [{"kind": "activity", "name": ".Main", "actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"]}])
    return build(m, dex_strings=["Landroid/app/Activity;", "onCreate", "https://example.org/help"], sign="release")
