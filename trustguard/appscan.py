"""Turns the static analysis of an Android app (``trustguard.extract.apk``) into findings, a verdict and a report.

Permissions are not treated as guilt: almost every app needs some, and many honest apps need SMS or location. What
matters is the combination - an app that *presents itself as a bank* and *can read your SMS* and *has a channel to send
data out* (a Telegram bot address in its code) is the pattern of the SMS-stealing "SBI Rewards" / "RTO Challan" APKs.
Each finding says what the app could do, why that matters, and what was seen; combination findings carry the families
of evidence they rest on, so a complete pattern is HIGH or CRITICAL while single capabilities stay WEAK.
"""
from __future__ import annotations

import re

from . import brands as B
from .extract.apk import APKInfo
from .findings import RawFinding
from .schemas import AppCertificate, AppComponent, AppPermission, AppReport
from .schemas import ScamCategory as C
from .schemas import Severity as SV
from .schemas import Strength as ST
from .url.parse import defang

_P = "android.permission."
# permission -> (risk, plain meaning)
PERMISSIONS: dict[str, tuple[str, str]] = {
    "READ_SMS": ("high", "read your SMS messages - including bank OTPs"),
    "RECEIVE_SMS": ("high", "receive your incoming SMS - including bank OTPs - as they arrive"),
    "RECEIVE_MMS": ("high", "receive your incoming MMS messages"),
    "RECEIVE_WAP_PUSH": ("high", "receive WAP push messages"),
    "SEND_SMS": ("high", "send SMS from your number (costly premium SMS, or spreading itself to your contacts)"),
    "READ_CALL_LOG": ("high", "read your call history"),
    "WRITE_CALL_LOG": ("high", "change your call history"),
    "PROCESS_OUTGOING_CALLS": ("high", "see and redirect the calls you make"),
    "CALL_PHONE": ("medium", "make phone calls - including USSD codes such as call forwarding - without you dialling"),
    "ANSWER_PHONE_CALLS": ("medium", "answer incoming calls"),
    "READ_PHONE_STATE": ("medium", "read your phone number, SIM and network details"),
    "READ_PHONE_NUMBERS": ("medium", "read your phone number(s)"),
    "READ_CONTACTS": ("medium", "read your contacts"),
    "WRITE_CONTACTS": ("medium", "change your contacts"),
    "GET_ACCOUNTS": ("medium", "see the accounts on the phone"),
    "ACCESS_FINE_LOCATION": ("medium", "know your precise location"),
    "ACCESS_COARSE_LOCATION": ("low", "know your approximate location"),
    "ACCESS_BACKGROUND_LOCATION": ("high", "track your location even when the app is closed"),
    "CAMERA": ("medium", "use the camera"),
    "RECORD_AUDIO": ("medium", "record audio with the microphone"),
    "SYSTEM_ALERT_WINDOW": ("high", "draw over other apps - used to show fake login screens on top of banking apps"),
    "REQUEST_INSTALL_PACKAGES": ("high", "install other apps"),
    "REQUEST_DELETE_PACKAGES": ("medium", "ask to uninstall other apps"),
    "QUERY_ALL_PACKAGES": ("medium", "see every installed app (banking trojans look for your banking apps)"),
    "MANAGE_EXTERNAL_STORAGE": ("high", "read and change all your files"),
    "READ_EXTERNAL_STORAGE": ("medium", "read your photos and files"),
    "WRITE_EXTERNAL_STORAGE": ("medium", "change your photos and files"),
    "READ_MEDIA_IMAGES": ("medium", "read your photos"),
    "BIND_ACCESSIBILITY_SERVICE": ("high", "read the screen and tap for you (accessibility service)"),
    "BIND_NOTIFICATION_LISTENER_SERVICE": ("high", "read every notification - including OTPs"),
    "BIND_DEVICE_ADMIN": ("high", "become a device administrator: hard to uninstall, can lock or wipe the phone"),
    "RECEIVE_BOOT_COMPLETED": ("low", "start automatically when the phone starts"),
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("low", "keep running in the background"),
    "FOREGROUND_SERVICE": ("low", "keep a service running"),
    "WAKE_LOCK": ("normal", "keep the phone awake"),
    "INTERNET": ("normal", "use the internet"),
    "ACCESS_NETWORK_STATE": ("normal", "see network connectivity"),
    "USE_FULL_SCREEN_INTENT": ("low", "show full-screen notifications"),
    "BLUETOOTH_CONNECT": ("low", "connect to Bluetooth devices"),
    "VIBRATE": ("normal", "vibrate the phone"),
}
CAPABILITIES = {"sms_send": "sends SMS from code", "sms_read": "reads or listens for SMS in its code", "sms_intercept": "can hide incoming SMS from you",
                "dynamic_code": "loads extra code at run time", "runtime_exec": "runs system commands", "root_tools": "looks for root / superuser tools",
                "device_ids": "reads device and SIM identifiers", "overlay": "asks for the 'draw over other apps' setting",
                "accessibility": "uses accessibility (screen reading / automatic taps)", "hide_icon": "can hide its own launcher icon",
                "screen_capture": "can capture the screen", "call_forward": "contains call-forwarding USSD codes",
                "exfil": "contains a data drop-off address (Telegram bot, webhook, Firebase database ...)", "upi": "builds UPI payment links",
                "contacts": "reads contacts in its code"}
_SMS_READ = {"READ_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH"}


def _short(p: str) -> str:
    return p[len(_P):] if p.startswith(_P) else p


def _claimed(info: APKInfo) -> B.Entity | None:
    text = f"{info.label} {re.sub(r'[._]', ' ', info.package)}"
    found = [e for e, *_ in B.find_entities(text) if e.kind in ("government", "bank", "payments", "telecom", "utility", "courier", "ecommerce", "crypto")]
    found = [e for e in found if e.key != "government_generic"] or found
    return found[0] if found else None


def build_report(info: APKInfo, claimed: B.Entity | None) -> AppReport:
    perms = []
    for p in info.permissions:
        s = _short(p)
        risk, meaning = PERMISSIONS.get(s, ("low" if p.startswith(_P) else "normal", "custom or less common permission"))
        perms.append(AppPermission(name=p, short=s, risk=risk, meaning=meaning))
    order = {"high": 0, "medium": 1, "low": 2, "normal": 3}
    perms.sort(key=lambda x: (order[x.risk], x.short))
    comps = []
    counts: dict[str, int] = {}
    for c in info.components:
        counts[c.kind] = counts.get(c.kind, 0) + 1
        role = _role(c)
        if c.exported or role:
            comps.append(AppComponent(kind=c.kind, name=c.name, exported=c.exported, permission=c.permission, actions=c.actions[:6], role=role))
    counts["exported"] = sum(c.exported for c in info.components)
    return AppReport(
        sha256=info.sha256, size_bytes=info.size, package=info.package, label=info.label, version_name=info.version_name, version_code=info.version_code,
        min_sdk=info.min_sdk, target_sdk=info.target_sdk, permissions=perms, declared_permissions=info.declared_permissions[:20], components=comps[:60],
        component_counts=counts, certificates=[AppCertificate(**vars(c)) for c in info.certificates], signature_schemes=info.signature_schemes,
        capabilities=[CAPABILITIES.get(k, k) for k in sorted(info.api_hits)], native_libs=info.native_libs[:40], packers=info.packers,
        embedded_code=info.embedded_code[:20], urls=[defang(u) for u in info.urls[:30]], domains=[defang(d) for d in info.domains[:30]],
        archive_issues=info.archive_issues[:10], limitations=info.limitations[:10], claimed_entity=claimed.name if claimed else None, parsed=info.manifest_ok)


def _role(c) -> str:
    perm = _short(c.permission or "")
    if c.kind == "service" and perm == "BIND_ACCESSIBILITY_SERVICE":
        return "accessibility service"
    if c.kind == "service" and perm == "BIND_NOTIFICATION_LISTENER_SERVICE":
        return "notification listener"
    if c.kind == "receiver" and perm == "BIND_DEVICE_ADMIN":
        return "device administrator"
    if c.kind == "receiver" and any("SMS_RECEIVED" in a or "WAP_PUSH" in a for a in c.actions):
        return f"SMS receiver{f' (priority {c.priority})' if c.priority else ''}"
    if c.kind == "receiver" and any(a.endswith("BOOT_COMPLETED") for a in c.actions):
        return "starts at boot"
    if c.kind == "service" and perm == "BIND_VPN_SERVICE":
        return "VPN service"
    return ""


def findings(info: APKInfo, claimed: B.Entity | None) -> list[RawFinding]:
    out: list[RawFinding] = []
    perms = {_short(p) for p in info.permissions}
    roles = {_role(c).split(" (")[0] for c in info.components} - {""}
    api = info.api_hits
    sms_read = bool(perms & _SMS_READ)
    sms_rx = [c for c in info.components if _role(c).startswith("SMS receiver")]
    high_prio_sms = any((c.priority or 0) >= 999 for c in sms_rx)
    exfil = bool(api.get("exfil")) or bool(info.ips)
    who = f"'{info.label}'" if info.label else "This app"

    def add(key, cat, title, sev, strength, conf, why, evidence, families=(), action="Don't install it. Get apps only from the Play Store."):
        out.append(RawFinding(key, cat, title, sev, strength, conf, why, action, "file", evidence=[e for e in evidence if e][:6], families=tuple(families)))

    add("apk_sideloaded", C.MALICIOUS_APP, "Android app from outside the Play Store", SV.LOW, ST.WEAK, 0.9,
        "Apps passed around as APK files skip Google Play's checks. Fake bank, e-challan and 'rewards' apps are spread this way, so treat any "
        "APK you were sent with suspicion - even if nothing below looks alarming.", [f"package: {info.package}" if info.package else ""])
    if claimed is not None:
        add("apk_impersonation", C.MALICIOUS_APP, f"Presents itself as {claimed.name}", SV.HIGH, ST.WEAK, 0.8,
            f"The app's name or package refers to {claimed.name}. Banks, government departments and big brands publish their apps on the Play "
            "Store; they don't send APK files by SMS or WhatsApp.", [f"name: {info.label}", f"package: {info.package}"],
            action=claimed.verify or "Install the organisation's official app from the Play Store instead.")
    # ---- SMS / OTP theft
    if sms_read:
        add("apk_sms_access", C.MALICIOUS_APP, "Can read your SMS - including OTPs", SV.HIGH, ST.WEAK, 0.8,
            "The app asks to read or receive SMS. Few apps need this; it is the core capability of the OTP-stealing apps behind most "
            "fake-APK frauds in India.", sorted(perms & _SMS_READ) + [_role(c) for c in sms_rx][:2])
    otp_reader = sms_read or "notification listener" in roles
    channel = exfil or high_prio_sms or bool(api.get("sms_intercept")) or bool(api.get("hide_icon"))
    if otp_reader and "INTERNET" in perms and (channel or claimed is not None):
        fam = ["reads OTPs (SMS or notifications)", "internet access"] + (["data drop-off address"] if exfil else []) \
            + (["hides SMS or icon"] if (api.get("sms_intercept") or api.get("hide_icon") or high_prio_sms) else []) + (["impersonation"] if claimed else [])
        add("apk_otp_theft", C.MALICIOUS_APP, "Built to steal OTPs: reads your messages and can send them out", SV.CRITICAL, ST.STRONG, 0.92,
            f"{who} can read your SMS or notifications (where bank OTPs arrive), has internet access, and "
            + ("contains an address for sending data out (e.g. a Telegram bot or a webhook)" if exfil else
               "intercepts or hides incoming SMS or its own icon" if channel else f"presents itself as {claimed.name}")
            + ". That combination is the design of SMS-stealing banking malware: OTPs are forwarded to fraudsters, who empty the account.",
            [f"domains: {', '.join(info.domains[:3])}" if info.domains else "", *(api.get("exfil") or [])[:2], *info.ips[:2]], fam,
            action="Don't install it. If you did: switch on airplane mode, uninstall it, call your bank to block cards and UPI, and report on 1930.")
    if "SEND_SMS" in perms:
        add("apk_sms_send", C.MALICIOUS_APP, "Can send SMS from your number", SV.MEDIUM, ST.WEAK, 0.75,
            "Sending SMS lets an app run up premium-SMS charges, register your number elsewhere or spread itself to your contacts.", ["SEND_SMS"])
    # ---- accessibility / overlays (banking trojans)
    if "accessibility service" in roles:
        add("apk_accessibility", C.MALICIOUS_APP, "Includes an accessibility service (can read the screen and tap)", SV.HIGH, ST.WEAK, 0.8,
            "Accessibility services are meant for users with disabilities. Banking trojans abuse them to read what's on the screen, grant "
            "themselves permissions and press buttons in banking apps.", [c.name for c in info.components if _role(c) == "accessibility service"][:2])
        if {"SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES"} & perms or sms_read or claimed is not None:
            add("apk_banking_trojan", C.MALICIOUS_APP, "Banking-trojan capabilities: screen control plus overlays, SMS or impersonation", SV.CRITICAL, ST.STRONG, 0.9,
                "The app combines an accessibility service with " + ", ".join(x for x in (
                    "drawing over other apps" if "SYSTEM_ALERT_WINDOW" in perms else "", "listing your installed apps" if "QUERY_ALL_PACKAGES" in perms else "",
                    "SMS access" if sms_read else "", f"pretending to be {claimed.name}" if claimed else "") if x)
                + ". Together these let an app watch you log in to your bank, show a fake screen on top and approve transactions itself.",
                [], ["screen control", "overlay / app list / SMS", "impersonation" if claimed else "sensitive access"])
    elif "SYSTEM_ALERT_WINDOW" in perms:
        add("apk_overlay", C.MALICIOUS_APP, "Can draw over other apps", SV.MEDIUM, ST.WEAK, 0.7,
            "Drawing over other apps is used legitimately by chat heads and screen filters, and maliciously to cover a banking app with a fake "
            "login screen.", ["SYSTEM_ALERT_WINDOW"])
    if "notification listener" in roles and not any(f.indicator == "apk_otp_theft" for f in out):
        add("apk_notification_reader", C.MALICIOUS_APP, "Reads all your notifications", SV.HIGH, ST.WEAK, 0.75,
            "A notification listener sees every notification, including OTPs from your bank and messages from other apps.", [])
    # ---- installing / loading other code
    if "REQUEST_INSTALL_PACKAGES" in perms and (info.embedded_code or api.get("dynamic_code")):
        add("apk_dropper", C.MALICIOUS_APP, "Installs or loads hidden code (dropper)", SV.HIGH, ST.STRONG, 0.85,
            "The app may install other apps and carries or loads additional code. Droppers look harmless at first and fetch the real malware later.",
            info.embedded_code[:2] + (api.get("dynamic_code") or [])[:1], ["installs apps", "hidden or run-time code"])
    elif "REQUEST_INSTALL_PACKAGES" in perms:
        add("apk_installer", C.MALICIOUS_APP, "Can install other apps", SV.MEDIUM, ST.WEAK, 0.7,
            "Being able to install other apps is how droppers deliver their real payload.", ["REQUEST_INSTALL_PACKAGES"])
    else:
        if info.embedded_code:
            add("apk_embedded_code", C.MALICIOUS_APP, "Carries extra code files inside the app", SV.MEDIUM, ST.WEAK, 0.7,
                "Code hidden in assets (DEX, JAR or another APK) can be loaded later, out of sight of a quick inspection.", info.embedded_code[:3])
        if api.get("dynamic_code"):
            add("apk_dynamic_code", C.MALICIOUS_APP, "Loads code at run time", SV.MEDIUM, ST.WEAK, 0.65,
                "Loading code at run time is used by plug-in systems and by malware that downloads its harmful part after installation.",
                api["dynamic_code"][:2])
    if info.packers:
        add("apk_packed", C.MALICIOUS_APP, "Protected with a commercial packer", SV.MEDIUM, ST.WEAK, 0.7,
            "Packers encrypt the real code so it can't be inspected. Some legitimate apps use them; much malware does too.", info.packers[:3])
    if info.non_elf_libs:
        add("apk_fake_native_lib", C.MALICIOUS_APP, "A 'native library' that isn't one", SV.MEDIUM, ST.WEAK, 0.75,
            "A file named like a native library is not a real program library - a common way to hide an encrypted payload.", info.non_elf_libs[:3])
    # ---- calls
    if api.get("call_forward"):
        strong = "CALL_PHONE" in perms
        add("apk_call_forwarding", C.MALICIOUS_APP, "Contains call-forwarding codes" + (" and can make calls" if strong else ""),
            SV.HIGH if strong else SV.MEDIUM, ST.STRONG if strong else ST.WEAK, 0.85 if strong else 0.7,
            "USSD codes such as *21* or *401* forward your calls to another number - fraudsters use this to receive your OTP calls and "
            "WhatsApp verification calls.", api["call_forward"][:2], ["call-forwarding codes", "can place calls"] if strong else ())
    if "device administrator" in roles:
        add("apk_device_admin", C.MALICIOUS_APP, "Asks to become a device administrator", SV.MEDIUM, ST.WEAK, 0.75,
            "Device administrators can lock or wipe the phone and are hard to uninstall.", [c.name for c in info.components if _role(c) == "device administrator"][:1])
    if exfil and not any(f.indicator == "apk_otp_theft" for f in out):
        add("apk_exfil_channel", C.MALICIOUS_APP, "Contains a data drop-off address", SV.MEDIUM, ST.WEAK, 0.7,
            "The code contains an address that receives data without a server of its own - a Telegram bot, a webhook, a Firebase database or a "
            "raw IP address. Stealer apps send what they collect there.", (api.get("exfil") or [])[:2] + info.ips[:2])
    if api.get("hide_icon") and any("android.intent.category.LAUNCHER" in c.categories for c in info.components):
        add("apk_hidden_icon", C.MALICIOUS_APP, "Can hide its own icon", SV.LOW, ST.WEAK, 0.6,
            "Apps that remove their launcher icon after installation are hard to find and uninstall.", api["hide_icon"][:1])
    if {"READ_CONTACTS", "ACCESS_FINE_LOCATION"} <= perms and {"CAMERA", "RECORD_AUDIO"} & perms:
        add("apk_privacy_reach", C.MALICIOUS_APP, "Broad access to personal data", SV.MEDIUM, ST.WEAK, 0.65,
            "Contacts, precise location and camera or microphone together give an app a detailed picture of your life.",
            sorted({"READ_CONTACTS", "ACCESS_FINE_LOCATION"} | ({"CAMERA", "RECORD_AUDIO"} & perms)))
    # ---- signing and build
    certs = info.certificates
    if any(c.test_key for c in certs):
        add("apk_test_key", C.MALICIOUS_APP, "Signed with Android's public test key", SV.HIGH, ST.WEAK, 0.8,
            "The signing key is the public AOSP test key, which anyone can use. Real publishers sign with their own private key; malware often doesn't bother.",
            [f"certificate SHA-256 {certs[0].sha256[:16]}..."])
    elif any(c.debug for c in certs):
        add("apk_debug_cert", C.MALICIOUS_APP, "Signed with a debug certificate", SV.MEDIUM, ST.WEAK, 0.7,
            "The app is signed with a development ('Android Debug') certificate. Published apps are never debug-signed.", [certs[0].subject[:60]])
    elif not certs and not info.signature_schemes:
        add("apk_unsigned", C.MALICIOUS_APP, "The app is not signed", SV.MEDIUM, ST.WEAK, 0.7,
            "No signature was found. Android refuses to install unsigned apps, so this file is incomplete, modified or meant to be installed by "
            "another app.", [])
    if info.debuggable:
        add("apk_debuggable", C.MALICIOUS_APP, "Built in debug mode", SV.LOW, ST.WEAK, 0.6,
            "A debuggable build is a development build; published apps aren't debuggable.", ["android:debuggable=true"])
    if info.target_sdk is not None and info.target_sdk < 23:
        add("apk_old_target", C.MALICIOUS_APP, f"Targets an old Android version (API {info.target_sdk})", SV.LOW, ST.WEAK, 0.6,
            "Apps that target Android 5 or older get all their permissions at install time, without the permission prompts newer Android shows.",
            [f"targetSdkVersion={info.target_sdk}"])
    if info.archive_issues:
        add("apk_archive_tricks", C.MALICIOUS_APP, "The archive is built to confuse inspection", SV.HIGH, ST.WEAK, 0.75,
            "The APK contains duplicate or unsafe file names. Legitimate build tools never produce these.", info.archive_issues[:3])
    return out


def confidence(info: APKInfo, level: str | None = None) -> float:
    """How much the static analysis could see. A LOW verdict is capped at medium confidence: reading an app's manifest
    and code strings can show that it is built to steal, but never prove that it is harmless (code can be downloaded
    after installation), so "low risk, high confidence" would overstate what was checked."""
    if not info.manifest_ok:
        return 0.3
    c = 0.65 + (0.1 if info.dex_files else -0.1) + (0.05 if info.certificates else 0.0)
    c -= 0.1 if info.limitations else 0.0
    if level == "LOW":
        c = min(c, 0.6)
    return round(max(0.3, min(c, 0.85)), 2)       # static analysis never gives high certainty about behaviour
