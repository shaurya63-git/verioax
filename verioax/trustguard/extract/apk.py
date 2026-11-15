"""Static analysis of Android apps (APK files) - read-only, offline, bounded.

What it does: opens the APK as a ZIP archive *in memory* and reads, within strict limits,
* ``AndroidManifest.xml`` (Android's binary XML): package, version, SDK levels, requested and declared permissions,
  activities / services / receivers / providers, whether they are exported, intent filters, accessibility and
  notification-listener services, device-admin receivers, debuggable / cleartext flags;
* ``resources.arsc`` only to turn the app label into text ("SBI Rewards" instead of a resource number);
* the signing certificate (v1 JAR signature in ``META-INF/*.RSA|DSA|EC`` and the v2/v3 APK Signing Block), to spot
  debug certificates and the public AOSP test key. The signature itself is **not** cryptographically verified;
* the string tables of the ``classes*.dex`` files: URLs, domains, IP addresses and API names that indicate SMS access,
  dynamic code loading, overlays, call forwarding or exfiltration channels (a Telegram bot, a Discord webhook);
* native libraries (ELF check, known commercial packers) and code files hidden in assets (droppers).

What it never does: install, execute or load the app, extract files to disk, follow its URLs, or send the file (or its
hash) anywhere. Limits stop ZIP bombs and malformed archives: entry count, declared and actual uncompressed sizes,
compression ratio, per-member read caps, path checks and an overall time budget. Anything that can't be read is
reported as a limitation, and an APK whose manifest can't be parsed is INCONCLUSIVE - never "safe".

Static analysis is not proof of malware (or of its absence): permissions are judged in combination, and every
finding says what the app *could* do, not what it did.
"""
from __future__ import annotations

import hashlib
import io
import re
import struct
import time
import zipfile
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------------------------- limits
MAX_ENTRIES = 40_000
MAX_TOTAL_UNCOMPRESSED = 1_000_000_000         # declared, whole archive
MAX_RATIO = 250                                 # declared uncompressed / compressed, per member we read
MAX_MANIFEST = 4 * 1024 * 1024
MAX_ARSC = 24 * 1024 * 1024
MAX_DEX_EACH = 48 * 1024 * 1024
MAX_DEX_TOTAL = 96 * 1024 * 1024
MAX_DEX_FILES = 12
MAX_DEX_STRINGS = 400_000
MAX_CERT = 1 * 1024 * 1024
MAX_SMALL = 2 * 1024 * 1024                     # assets checked for embedded code
TIME_BUDGET_S = 25.0

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_ATTR_IDS = {0x01010001: "label", 0x01010002: "icon", 0x01010003: "name", 0x01010006: "permission", 0x01010009: "protectionLevel",
             0x0101000b: "sharedUserId", 0x0101000e: "enabled", 0x0101000f: "debuggable", 0x01010010: "exported", 0x0101001c: "priority",
             0x01010027: "scheme", 0x01010028: "host", 0x0101020c: "minSdkVersion", 0x0101021b: "versionCode", 0x0101021c: "versionName",
             0x01010270: "targetSdkVersion", 0x01010280: "allowBackup", 0x010104ec: "usesCleartextTraffic"}


class APKError(ValueError):
    """The file is not an APK we can read safely."""


@dataclass
class Component:
    kind: str                                   # activity | activity-alias | service | receiver | provider
    name: str
    exported: bool
    permission: str | None
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    priority: int | None = None


@dataclass
class Certificate:
    source: str                                 # v1 | v2 | v3
    subject: str
    issuer: str
    sha256: str
    not_before: str | None
    not_after: str | None
    key: str
    self_signed: bool
    debug: bool
    test_key: bool


@dataclass
class APKInfo:
    sha256: str
    size: int
    package: str = ""
    label: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = field(default_factory=list)
    declared_permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    debuggable: bool = False
    cleartext: bool | None = None
    allow_backup: bool | None = None
    certificates: list[Certificate] = field(default_factory=list)
    signature_schemes: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    non_elf_libs: list[str] = field(default_factory=list)
    packers: list[str] = field(default_factory=list)
    embedded_code: list[str] = field(default_factory=list)
    dex_files: int = 0
    dex_strings_scanned: int = 0
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    api_hits: dict[str, list[str]] = field(default_factory=dict)       # capability -> example strings
    archive_issues: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    manifest_ok: bool = False
    entries: int = 0


# ---------------------------------------------------------------------------------------------- safe ZIP access
def looks_like_apk(name: str, data: bytes) -> bool:
    if data[:4] != b"PK\x03\x04":
        return False
    if (name or "").lower().endswith((".apk", ".apks", ".xapk")):
        return True
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = set(z.namelist()[:MAX_ENTRIES])
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError):
        return False
    return "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names)


class _Archive:
    def __init__(self, data: bytes, deadline: float):
        self.deadline = deadline
        try:
            self.z = zipfile.ZipFile(io.BytesIO(data))
            self.infos = self.z.infolist()
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError, struct.error) as exc:
            raise APKError(f"the file is not a readable ZIP/APK archive ({type(exc).__name__})") from None
        if len(self.infos) > MAX_ENTRIES:
            raise APKError(f"the archive has {len(self.infos):,} entries (limit {MAX_ENTRIES:,}) - refusing to process it")
        total = sum(i.file_size for i in self.infos)
        if total > MAX_TOTAL_UNCOMPRESSED:
            raise APKError(f"the archive would expand to {total / 1e9:.1f} GB - refusing to process it (possible ZIP bomb)")
        self.by_name: dict[str, zipfile.ZipInfo] = {}
        self.issues: list[str] = []
        seen: set[str] = set()
        for i in self.infos:
            n = i.filename
            if n in seen:
                self.issues.append(f"duplicate entry '{n[:80]}' (the 'Master Key' trick that hides code from signature checks)")
            seen.add(n)
            if n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/") or re.match(r"^[A-Za-z]:", n):
                self.issues.append(f"unsafe path '{n[:80]}' (path traversal)")
            self.by_name.setdefault(n, i)

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise TimeoutError

    def read(self, name: str, cap: int) -> bytes | None:
        """Read one member with a hard cap on the bytes produced (declared sizes can lie)."""
        info = self.by_name.get(name)
        if info is None:
            return None
        if info.flag_bits & 0x1:
            raise APKError(f"'{name}' is encrypted")
        if info.file_size > cap:
            return None
        if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_RATIO and info.file_size > 1_000_000:
            self.issues.append(f"'{name[:60]}' has a compression ratio above {MAX_RATIO}:1 - not read")
            return None
        self.check_time()
        out = bytearray()
        with self.z.open(info) as f:
            while True:
                chunk = f.read(1 << 16)
                if not chunk:
                    break
                out += chunk
                if len(out) > cap:
                    self.issues.append(f"'{name[:60]}' is larger than it declares - not read")
                    return None
        return bytes(out)


# ---------------------------------------------------------------------------------------------- binary XML (AXML)
def _string_pool(buf: bytes, off: int) -> list[str]:
    _t, hsize, size = struct.unpack_from("<HHI", buf, off)
    count, _styles, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", buf, off + 8)
    if count > 500_000:
        raise APKError("string pool too large")
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", buf, off + hsize)
    base = off + strings_start
    end = off + size
    out = []
    for o in offsets:
        p = base + o
        if p >= end:
            out.append("")
            continue
        try:
            if utf8:
                n = buf[p]
                p += 2 if n & 0x80 else 1                 # length in characters (skipped)
                n = buf[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | buf[p + 1]
                    p += 2
                else:
                    p += 1
                out.append(buf[p:p + n].decode("utf-8", errors="replace"))
            else:
                n = struct.unpack_from("<H", buf, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p)[0]
                    p += 2
                out.append(buf[p:p + n * 2].decode("utf-16-le", errors="replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


@dataclass
class _Node:
    tag: str
    attrs: dict[str, object]
    children: list[_Node] = field(default_factory=list)


def parse_axml(buf: bytes) -> _Node:
    """Android binary XML -> a small element tree. Attribute names use the 'android:' namespace names."""
    if len(buf) < 8:
        raise APKError("AndroidManifest.xml is empty")
    typ, hsize, size = struct.unpack_from("<HHI", buf, 0)
    if typ != 0x0003:
        if buf.lstrip().startswith(b"<"):
            raise APKError("AndroidManifest.xml is plain text (not a compiled app)")
        raise APKError("AndroidManifest.xml is not Android binary XML")
    strings: list[str] = []
    res_ids: list[int] = []
    root = _Node("#document", {})
    stack = [root]
    off = hsize
    end = min(size, len(buf))
    guard = 0
    while off + 8 <= end:
        guard += 1
        if guard > 500_000:
            raise APKError("manifest has too many elements")
        ctype, chsize, csize = struct.unpack_from("<HHI", buf, off)
        if csize < 8 or off + csize > end:
            break
        if ctype == 0x0001:
            strings = _string_pool(buf, off)
        elif ctype == 0x0180:
            res_ids = list(struct.unpack_from(f"<{(csize - chsize) // 4}I", buf, off + chsize))
        elif ctype == 0x0102:                              # start element
            ext = off + chsize
            _ns, name_i, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", buf, ext)
            tag = strings[name_i] if name_i < len(strings) else "?"
            attrs: dict[str, object] = {}
            for k in range(min(attr_count, 400)):
                a = ext + attr_start + k * attr_size
                ans, aname, raw, _vsize, _res0, vtype, vdata = struct.unpack_from("<IIIHBBI", buf, a)
                key = strings[aname] if aname < len(strings) else ""
                if aname < len(res_ids) and res_ids[aname] in _ATTR_IDS:
                    key = _ATTR_IDS[res_ids[aname]]          # the resource id is authoritative (obfuscators rename the strings)
                if raw != 0xFFFFFFFF and raw < len(strings):
                    val: object = strings[raw]
                elif vtype == 0x03 and vdata < len(strings):
                    val = strings[vdata]
                elif vtype == 0x12:
                    val = vdata != 0
                elif vtype in (0x10, 0x11):
                    val = struct.unpack("<i", struct.pack("<I", vdata))[0]
                elif vtype == 0x01:
                    val = f"@0x{vdata:08x}"
                else:
                    val = vdata
                attrs[key] = val
            node = _Node(tag, attrs)
            stack[-1].children.append(node)
            stack.append(node)
        elif ctype == 0x0103 and len(stack) > 1:
            stack.pop()
        off += csize
    manifest = next((c for c in root.children if c.tag == "manifest"), None)
    if manifest is None:
        raise APKError("AndroidManifest.xml has no <manifest> element")
    return manifest


# ---------------------------------------------------------------------------------------------- resources (app label only)
def resolve_string(arsc: bytes, res_id: int) -> str | None:
    """The default-language string value of resource ``res_id`` (0x7fTTEEEE) in resources.arsc, or None."""
    try:
        typ, hsize, size = struct.unpack_from("<HHI", arsc, 0)
        if typ != 0x0002:
            return None
        pkg_id, type_id, entry_id = res_id >> 24, (res_id >> 16) & 0xFF, res_id & 0xFFFF
        off = hsize
        global_strings: list[str] = []
        best: tuple[int, str] | None = None
        while off + 8 <= min(size, len(arsc)):
            ctype, chsize, csize = struct.unpack_from("<HHI", arsc, off)
            if csize < 8:
                break
            if ctype == 0x0001:
                global_strings = _string_pool(arsc, off)
            elif ctype == 0x0200:
                pid = struct.unpack_from("<I", arsc, off + 8)[0]
                if pid == pkg_id:
                    p = off + chsize
                    pend = off + csize
                    while p + 8 <= pend:
                        t2, h2, s2 = struct.unpack_from("<HHI", arsc, p)
                        if s2 < 8:
                            break
                        if t2 == 0x0201:
                            tid, flags, _r, count, entries_start = struct.unpack_from("<BBHII", arsc, p + 8)
                            if tid == type_id and entry_id < count and not flags & 0x01:
                                cfg = p + 20
                                lang = arsc[cfg + 8:cfg + 12]
                                if flags & 0x02:            # 16-bit offsets
                                    eo = struct.unpack_from("<H", arsc, p + h2 + entry_id * 2)[0]
                                    eo = 0xFFFFFFFF if eo == 0xFFFF else eo * 4
                                else:
                                    eo = struct.unpack_from("<I", arsc, p + h2 + entry_id * 4)[0]
                                if eo != 0xFFFFFFFF:
                                    e = p + entries_start + eo
                                    esize, eflags = struct.unpack_from("<HH", arsc, e)
                                    if not eflags & 0x0001 and not eflags & 0x0008:
                                        _vs, _z, vtype, vdata = struct.unpack_from("<HBBI", arsc, e + esize)
                                        if vtype == 0x03 and vdata < len(global_strings):
                                            rank = 0 if lang == b"\x00\x00\x00\x00" else 1
                                            if best is None or rank < best[0]:
                                                best = (rank, global_strings[vdata])
                        p += s2
            off += csize
        return best[1] if best else None
    except (struct.error, IndexError):
        return None


# ---------------------------------------------------------------------------------------------- signing certificates
def _certs_from_v1(der: bytes) -> list:
    from cryptography.hazmat.primitives.serialization import pkcs7
    return list(pkcs7.load_der_pkcs7_certificates(der))


def _signing_block(data: bytes) -> dict[int, bytes]:
    """ID -> value pairs of the APK Signing Block (v2 / v3 signatures), located just before the ZIP central directory."""
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 70_000))
    if eocd < 0 or eocd + 22 > len(data):
        return {}
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    if cd_off < 32 or cd_off > len(data) or data[cd_off - 16:cd_off] != b"APK Sig Block 42":
        return {}
    size = struct.unpack_from("<Q", data, cd_off - 24)[0]
    start = cd_off - size - 8
    if start < 0 or size > 64 * 1024 * 1024:
        return {}
    p, end, out = start + 8, cd_off - 24, {}
    while p + 12 <= end:
        ln = struct.unpack_from("<Q", data, p)[0]
        if ln < 4 or p + 8 + ln > end:
            break
        pid = struct.unpack_from("<I", data, p + 8)[0]
        out[pid] = data[p + 12:p + 8 + ln]
        p += 8 + ln
    return out


def _lp(buf: bytes, p: int) -> tuple[bytes, int]:
    n = struct.unpack_from("<I", buf, p)[0]
    return buf[p + 4:p + 4 + n], p + 4 + n


def _certs_from_v2v3(value: bytes) -> list[bytes]:
    out = []
    signers, _ = _lp(value, 0)
    p = 0
    while p + 4 <= len(signers) and len(out) < 5:
        signer, p = _lp(signers, p)
        signed, _ = _lp(signer, 0)
        _digests, q = _lp(signed, 0)
        certs, _ = _lp(signed, q)
        r = 0
        while r + 4 <= len(certs):
            der, r = _lp(certs, r)
            out.append(der)
    return out


def _describe(cert, source: str) -> Certificate:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    pub = cert.public_key()
    key = (f"RSA {pub.key_size}" if isinstance(pub, rsa.RSAPublicKey) else f"EC {pub.curve.name}" if isinstance(pub, ec.EllipticCurvePublicKey)
           else f"DSA {pub.key_size}" if isinstance(pub, dsa.DSAPublicKey) else type(pub).__name__)
    subject, issuer = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
    low = subject.lower()
    debug = "cn=android debug" in low
    test_key = ("emailaddress=android@android.com" in low or "1.2.840.113549.1.9.1=android@android.com" in low) and "o=android" in low
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return Certificate(source, subject[:300], issuer[:300], cert.fingerprint(hashes.SHA256()).hex(), nb.date().isoformat(), na.date().isoformat(),
                       key, subject == issuer, debug, test_key)


# ---------------------------------------------------------------------------------------------- DEX strings
def _uleb(buf: bytes, p: int) -> tuple[int, int]:
    result = shift = 0
    for _ in range(5):
        b = buf[p]
        p += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return result, p


def dex_strings(dex: bytes, limit: int) -> list[str]:
    if len(dex) < 0x70 or not dex.startswith(b"dex\n"):
        raise APKError("not a DEX file")
    count, ids_off = struct.unpack_from("<II", dex, 0x38)
    count = min(count, limit)
    out = []
    for i in range(count):
        try:
            p = struct.unpack_from("<I", dex, ids_off + i * 4)[0]
            _n, p = _uleb(dex, p)
            e = dex.index(b"\x00", p, min(len(dex), p + 4096))
            out.append(dex[p:e].decode("utf-8", errors="replace"))
        except (struct.error, ValueError, IndexError):
            break
    return out


# capability -> patterns over DEX strings (class names, method names, constants)
_API = {
    "sms_send": (r"^Landroid/telephony/(?:gsm/)?SmsManager;$", r"^sendTextMessage$", r"^sendMultipartTextMessage$"),
    "sms_read": (r"^content://sms", r"^android\.provider\.Telephony\.SMS_RECEIVED$", r"^getMessageBody$", r"^createFromPdu$"),
    "sms_intercept": (r"^abortBroadcast$",),
    "dynamic_code": (r"^Ldalvik/system/(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader|BaseDexClassLoader);$",),
    "root_tools": (r"^/system/(?:x?bin)/su$", r"^/sbin/su$", r"^busybox$", r"^Superuser\.apk$", r"^/system/app/Superuser\.apk$"),
    "device_ids": (r"^getDeviceId$", r"^getSubscriberId$", r"^getLine1Number$", r"^getSimSerialNumber$", r"^getImei$"),
    "overlay": (r"^android\.settings\.action\.MANAGE_OVERLAY_PERMISSION$",),
    "accessibility": (r"^Landroid/accessibilityservice/AccessibilityService;$", r"^performGlobalAction$", r"^dispatchGesture$"),
    "hide_icon": (r"^setComponentEnabledSetting$",),
    "screen_capture": (r"^Landroid/media/projection/MediaProjection;$",),
    "call_forward": (r"^(?:tel:)?\*{1,2}(?:21|61|62|67|401)\*", r"%2A21%2A", r"^\*401\*"),
    "exfil": (r"api\.telegram\.org/bot", r"discord(?:app)?\.com/api/webhooks", r"\.firebaseio\.com", r"pastebin\.com/raw", r"\.ngrok(?:-free)?\.(?:io|app)",
              r"\.duckdns\.org", r"webhook\.site", r"\.trycloudflare\.com"),
    "upi": (r"^upi://pay", r"^upi://"),
    "contacts": (r"^content://com\.android\.contacts", r"^Landroid/provider/ContactsContract",),
}
_API_RX = {k: [re.compile(p) for p in v] for k, v in _API.items()}
_URL_RX = re.compile(r"https?://[A-Za-z0-9.\-]{3,253}(?::\d{2,5})?(?:/[^\s\"'<>]{0,200})?")
_IP_RX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?$|https?://(?:\d{1,3}\.){3}\d{1,3}")
_BORING = ("schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org", "googleapis.com", "google.com", "gstatic.com", "android.com",
           "googlesyndication.com", "google-analytics.com", "googleadservices.com", "doubleclick.net", "crashlytics.com", "facebook.com",
           "fb.com", "instagram.com", "youtube.com", "example.com", "github.com", "jetbrains.org", "kotlinlang.org", "ns.adobe.com",
           "purl.org", "xml.org", "json.org", "mozilla.org", "apple.com", "firebase.google.com", "app-measurement.com", "play.google.com")
_PACKERS = {"libjiagu": "Qihoo 360 Jiagu", "libsecexe": "Bangcle", "libsecmain": "Bangcle", "libdexhelper": "SecNeo", "libprotectclass": "ijiami",
            "libexec": "ijiami", "libexecmain": "ijiami", "libshella": "Tencent Legu", "libshellx": "Tencent Legu", "libtup": "Tencent",
            "libnqshield": "NQ Shield", "libapkprotect": "APKProtect", "libbaiduprotect": "Baidu", "libmobisec": "Alibaba", "libappguard": "AppGuard",
            "libsgmain": "Alibaba", "libjiaguarm": "Qihoo 360 Jiagu", "libnesec": "NetEase", "libdexprotect": "DexProtector"}


# ---------------------------------------------------------------------------------------------- analysis
def analyze_apk(data: bytes, *, time_budget_s: float = TIME_BUDGET_S) -> APKInfo:
    """Parse an APK within the limits above. Raises APKError when the archive or its manifest can't be read."""
    info = APKInfo(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    arc = _Archive(data, time.monotonic() + time_budget_s)
    info.entries = len(arc.infos)
    info.archive_issues = list(arc.issues)
    try:
        man = arc.read("AndroidManifest.xml", MAX_MANIFEST)
        if man is None:
            raise APKError("the archive has no readable AndroidManifest.xml - it is not an Android app (or it is malformed)")
        node = parse_axml(man)
        _manifest(node, info)
        info.manifest_ok = True
        if info.label.startswith("@0x"):
            arsc = arc.read("resources.arsc", MAX_ARSC)
            resolved = resolve_string(arsc, int(info.label[3:], 16)) if arsc else None
            info.label = resolved or ""
            if not resolved:
                info.limitations.append("the app's display name could not be resolved from its resources")
        _signatures(arc, data, info)
        _code(arc, info)
        info.archive_issues = list(dict.fromkeys(arc.issues))
    except TimeoutError:
        info.limitations.append(f"analysis stopped after {time_budget_s:.0f} s: some parts of the app were not examined")
    except (struct.error, IndexError) as exc:
        if not info.manifest_ok:
            raise APKError(f"AndroidManifest.xml is malformed ({type(exc).__name__})") from None
        info.limitations.append(f"part of the app could not be parsed ({type(exc).__name__})")
    return info


def _bool(v) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ("true", "false"):
        return v.lower() == "true"
    return None


def _int(v) -> int | None:
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v)
    return None


def _manifest(m: _Node, info: APKInfo) -> None:
    info.package = str(m.attrs.get("package", ""))[:200]
    info.version_name = str(m.attrs.get("versionName", "") or "")[:60]
    info.version_code = str(m.attrs.get("versionCode", "") or "")[:20]
    for c in m.children:
        if c.tag == "uses-sdk":
            info.min_sdk, info.target_sdk = _int(c.attrs.get("minSdkVersion")), _int(c.attrs.get("targetSdkVersion"))
        elif c.tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
            name = str(c.attrs.get("name", ""))
            if name and name not in info.permissions:
                info.permissions.append(name[:200])
        elif c.tag == "permission":
            info.declared_permissions.append(str(c.attrs.get("name", ""))[:200])
        elif c.tag == "application":
            label = c.attrs.get("label", "")
            info.label = str(label)[:200] if label is not None else ""
            info.debuggable = bool(_bool(c.attrs.get("debuggable")))
            info.cleartext = _bool(c.attrs.get("usesCleartextTraffic"))
            info.allow_backup = _bool(c.attrs.get("allowBackup"))
            target = info.target_sdk or 0
            for comp in c.children:
                if comp.tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
                    continue
                filters = [f for f in comp.children if f.tag == "intent-filter"]
                actions = [str(a.attrs.get("name", "")) for f in filters for a in f.children if a.tag == "action"]
                cats = [str(a.attrs.get("name", "")) for f in filters for a in f.children if a.tag == "category"]
                prio = max((_int(f.attrs.get("priority")) or 0 for f in filters), default=None)
                explicit = _bool(comp.attrs.get("exported"))
                exported = explicit if explicit is not None else (bool(filters) if target < 31 else False)
                if comp.tag == "provider" and explicit is None:
                    exported = target < 17
                info.components.append(Component(comp.tag, str(comp.attrs.get("name", ""))[:200], exported,
                                                 str(comp.attrs["permission"])[:200] if comp.attrs.get("permission") else None,
                                                 actions[:20], cats[:10], prio))


def _signatures(arc: _Archive, data: bytes, info: APKInfo) -> None:
    try:
        from cryptography import x509
    except ImportError:                                     # pragma: no cover - cryptography is a core dependency
        info.limitations.append("the 'cryptography' package is missing, so the signing certificate was not read")
        return
    seen: set[str] = set()
    for name in arc.by_name:
        if re.fullmatch(r"META-INF/[^/]+\.(?:RSA|DSA|EC)", name, re.I):
            der = arc.read(name, MAX_CERT)
            if der:
                try:
                    for cert in _certs_from_v1(der):
                        c = _describe(cert, "v1")
                        if c.sha256 not in seen:
                            seen.add(c.sha256)
                            info.certificates.append(c)
                    info.signature_schemes.append("v1 (JAR)")
                except Exception:
                    info.limitations.append(f"the v1 signature file {name} could not be parsed")
    try:
        block = _signing_block(data)
    except struct.error:
        block = {}
    for pid, label in ((0x7109871A, "v2"), (0xF05368C0, "v3"), (0x1B93AD61, "v3.1")):
        if pid in block:
            info.signature_schemes.append(f"{label} (APK Signature Scheme)")
            try:
                for der in _certs_from_v2v3(block[pid]):
                    c = _describe(x509.load_der_x509_certificate(der), label)
                    if c.sha256 not in seen:
                        seen.add(c.sha256)
                        info.certificates.append(c)
            except Exception:
                info.limitations.append(f"the {label} signing block could not be parsed")
    info.signature_schemes = list(dict.fromkeys(info.signature_schemes))


def _code(arc: _Archive, info: APKInfo) -> None:
    names = list(arc.by_name)
    dex_names = sorted(n for n in names if re.fullmatch(r"classes\d*\.dex", n))
    budget = MAX_DEX_TOTAL
    hits: dict[str, set[str]] = {}
    urls: set[str] = set()
    ips: set[str] = set()
    exec_seen = [False, False]
    for n in dex_names[:MAX_DEX_FILES]:
        arc.check_time()
        size = arc.by_name[n].file_size
        if size > min(MAX_DEX_EACH, budget):
            info.limitations.append(f"{n} ({size / 1e6:.1f} MB) is above the size limit and was not scanned")
            continue
        dex = arc.read(n, min(MAX_DEX_EACH, budget))
        if dex is None:
            continue
        budget -= len(dex)
        info.dex_files += 1
        try:
            strings = dex_strings(dex, MAX_DEX_STRINGS)
        except APKError:
            info.limitations.append(f"{n} is not a valid DEX file")
            continue
        info.dex_strings_scanned += len(strings)
        for s in strings:
            if len(s) > 2000:
                continue
            if s == "Ljava/lang/Runtime;":
                exec_seen[0] = True
            elif s == "exec":
                exec_seen[1] = True
            for cap, rxs in _API_RX.items():
                if any(rx.search(s) for rx in rxs):
                    hits.setdefault(cap, set()).add(s[:120])
            if "http" in s:
                urls.update(u.rstrip(".,;)") for u in _URL_RX.findall(s))
            if _IP_RX.search(s):
                ips.add(s[:60])
    if len(dex_names) > MAX_DEX_FILES:
        info.limitations.append(f"only the first {MAX_DEX_FILES} of {len(dex_names)} DEX files were scanned")
    if not dex_names:
        info.limitations.append("the app contains no classes.dex (code may be loaded at run time or the APK is a split/resource package)")
    if exec_seen[0] and exec_seen[1]:                       # Runtime.exec(...): both names appear in the string table
        hits.setdefault("runtime_exec", set()).add("java.lang.Runtime.exec")
    info.api_hits = {k: sorted(v)[:5] for k, v in hits.items()}
    info.ips = sorted(ips)[:20]
    interesting = []
    for u in sorted(urls):
        host = re.sub(r"^https?://", "", u).split("/")[0].split(":")[0].lower()
        if not any(host == b or host.endswith("." + b) for b in _BORING):
            interesting.append(u)
    info.urls = interesting[:40]
    info.domains = sorted({re.sub(r"^https?://", "", u).split("/")[0].split(":")[0].lower() for u in interesting})[:40]
    # native libraries and hidden code
    for n in names:
        low = n.lower()
        if low.startswith("lib/") and low.endswith(".so"):
            base = low.rsplit("/", 1)[-1]
            info.native_libs.append(n[:120])
            stem = re.sub(r"(?:_?(?:arm|x86|a64|v7a)\w*)?\.so$", "", base)
            for key, vendor in _PACKERS.items():
                if stem == key or stem.startswith(key):
                    info.packers.append(vendor)
            head = arc.read(n, 64 * 1024 * 1024) if arc.by_name[n].file_size <= 64 * 1024 * 1024 else None
            if head is not None and not head.startswith(b"\x7fELF"):
                info.non_elf_libs.append(n[:120])
        elif low.startswith(("assets/", "res/raw/")) and low.endswith((".dex", ".jar", ".apk", ".odex", ".zip")):
            blob = arc.read(n, MAX_SMALL)
            if blob is not None and (blob.startswith(b"dex\n") or blob.startswith(b"PK\x03\x04")):
                info.embedded_code.append(n[:120])
            elif blob is None:
                info.embedded_code.append(n[:120] + " (not examined: too large)")
    info.native_libs = sorted(set(info.native_libs))[:60]
    info.packers = sorted(set(info.packers))
