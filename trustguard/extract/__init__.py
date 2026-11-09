"""Text extraction for the File Scanner: TXT, CSV, PDF, DOCX and images (OCR).

Every extractor returns one text plus a list of blocks (start, end, location) so that a finding at any offset can be
traced back to "page 2", "table 1, row 3" or "line 14". Incomplete extraction is never silent: pages without a text
layer, OCR that is not installed, or files cut at the size limit all become warnings on the result.
"""
from __future__ import annotations

import csv
import io
import re
import shutil
from bisect import bisect_right
from dataclasses import dataclass, field

MAX_CHARS = 200_000
TEXT_TYPES = {".txt", ".csv", ".md", ".log", ".eml"}
IMAGE_TYPES = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}
SUPPORTED = TEXT_TYPES | IMAGE_TYPES | {".pdf", ".docx"}


class ExtractionError(ValueError):
    pass


@dataclass
class Extracted:
    text: str
    format: str
    blocks: list[tuple[int, int, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    pages: int | None = None
    ocr_used: bool = False

    def locate(self, pos: int) -> str:
        starts = [b[0] for b in self.blocks]
        i = bisect_right(starts, pos) - 1
        return self.blocks[i][2] if i >= 0 else "document"


class _Builder:
    def __init__(self, fmt: str):
        self.parts: list[str] = []
        self.blocks: list[tuple[int, int, str]] = []
        self.pos = 0
        self.fmt = fmt
        self.warnings: list[str] = []
        self.truncated = False

    def add(self, text: str, location: str) -> None:
        text = text.strip("\n")
        if not text.strip() or self.truncated:
            return
        if self.pos + len(text) > MAX_CHARS:
            text = text[: max(0, MAX_CHARS - self.pos)]
            self.truncated = True
            self.warnings.append(f"file truncated: only the first {MAX_CHARS:,} characters were analysed")
        sep = "\n\n" if self.parts else ""
        start = self.pos + len(sep)
        self.parts.append(sep + text)
        self.blocks.append((start, start + len(text), location))
        self.pos = start + len(text)

    def done(self, **kw) -> Extracted:
        return Extracted("".join(self.parts), self.fmt, self.blocks, self.warnings, **kw)


def sniff(name: str, data: bytes) -> str:
    head = data[:8]
    if head.startswith(b"%PDF"):
        return ".pdf"
    if head.startswith(b"PK"):
        return ".docx"
    if head.startswith(b"\x89PNG"):
        return ".png"
    if head[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if head.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ".webp"
    m = re.search(r"\.[A-Za-z0-9]+$", name or "")
    return m.group().lower() if m else ""


def ocr_available() -> bool:
    if shutil.which("tesseract") is None:
        return False
    try:
        import pytesseract  # noqa: F401
        return True
    except ImportError:
        return False


def _ocr(image) -> str:
    import pytesseract
    langs = "eng+hin" if "hin" in (pytesseract.get_languages(config="") or []) else "eng"
    return pytesseract.image_to_string(image, lang=langs)


def extract(name: str, data: bytes) -> Extracted:
    if not data:
        raise ExtractionError("the file is empty")
    ext = sniff(name, data)
    if ext not in SUPPORTED:
        raise ExtractionError(f"unsupported file type '{ext or 'unknown'}'. Supported: PDF, DOCX, TXT, CSV, PNG, JPG")
    if ext in TEXT_TYPES:
        return _text(data, ext)
    if ext == ".pdf":
        return _pdf(data)
    if ext == ".docx":
        return _docx(data)
    return _image(data)


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def _text(data: bytes, ext: str) -> Extracted:
    raw = _decode(data)
    b = _Builder(ext.lstrip("."))
    if ext == ".csv":
        try:
            rows = list(csv.reader(io.StringIO(raw)))
        except csv.Error as exc:
            raise ExtractionError(f"could not parse CSV: {exc}") from None
        for i, row in enumerate(rows, start=1):
            b.add(" | ".join(c.strip() for c in row), f"row {i}")
        return b.done()
    lines = raw.splitlines()
    chunk, start_line = [], 1
    for i, line in enumerate(lines, start=1):
        chunk.append(line)
        if len(chunk) >= 20 or i == len(lines):
            b.add("\n".join(chunk), f"lines {start_line}-{i}" if i > start_line else f"line {i}")
            chunk, start_line = [], i + 1
    return b.done()


def _pdf(data: bytes) -> Extracted:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                raise ExtractionError("the PDF is password-protected") from None
        pages = reader.pages
    except PdfReadError as exc:
        raise ExtractionError(f"could not read the PDF: {exc}") from None
    b = _Builder("pdf")
    no_text: list[int] = []
    ocr_used = False
    can_ocr = ocr_available()
    for n, page in enumerate(pages, start=1):
        try:
            txt = page.extract_text() or ""
        except Exception:                                       # a broken page must not stop the rest
            txt = ""
            b.warnings.append(f"page {n}: text layer could not be read")
        if len(txt.strip()) < 20:
            if can_ocr:
                img_text = _ocr_pdf_page(page)
                if img_text.strip():
                    txt, ocr_used = img_text, True
            if len(txt.strip()) < 20:
                no_text.append(n)
        b.add(txt, f"page {n}")
    if no_text:
        how = "and OCR found no text" if can_ocr else "and OCR is not installed (install Tesseract to read scans)"
        b.warnings.append(f"no text layer on page(s) {_ranges(no_text)} {how}")
    return b.done(pages=len(pages), ocr_used=ocr_used)


def _ocr_pdf_page(page) -> str:
    """OCR the embedded images of a scanned page (pure-Python path: no PDF rasteriser required)."""
    from PIL import Image
    out = []
    try:
        for im in page.images:
            with Image.open(io.BytesIO(im.data)) as pic:
                out.append(_ocr(pic.convert("RGB")))
    except Exception:
        return ""
    return "\n".join(out)


def _docx(data: bytes) -> Extracted:
    try:
        import docx
        d = docx.Document(io.BytesIO(data))
    except Exception as exc:
        raise ExtractionError(f"could not read the DOCX file ({type(exc).__name__})") from None
    b = _Builder("docx")
    for i, p in enumerate(d.paragraphs, start=1):
        b.add(p.text, f"paragraph {i}")
    for t, table in enumerate(d.tables, start=1):
        for r, row in enumerate(table.rows, start=1):
            cells = []
            for c in row.cells:
                if not cells or cells[-1] != c.text:            # merged cells repeat their text
                    cells.append(c.text)
            b.add(" | ".join(x.strip() for x in cells), f"table {t}, row {r}")
    for s, section in enumerate(d.sections, start=1):
        for kind, part in (("header", section.header), ("footer", section.footer)):
            txt = "\n".join(p.text for p in part.paragraphs if p.text.strip())
            b.add(txt, f"section {s} {kind}")
    if not b.parts:
        b.warnings.append("the document contains no text (images inside DOCX files are not OCR'd)")
    return b.done()


def _image(data: bytes) -> Extracted:
    b = _Builder("image")
    if not ocr_available():
        raise ExtractionError("reading images needs OCR: install Tesseract (see README) and the 'ocr' extra")
    from PIL import Image, ImageOps
    try:
        with Image.open(io.BytesIO(data)) as pic:
            img = ImageOps.exif_transpose(pic).convert("RGB")
            if max(img.size) < 1200:                            # small screenshots OCR better when upscaled
                scale = 1200 / max(img.size)
                img = img.resize((int(img.width * scale), int(img.height * scale)))
            text = _ocr(img)
    except (OSError, ValueError) as exc:
        raise ExtractionError(f"could not read the image: {exc}") from None
    for i, block in enumerate(re.split(r"\n\s*\n", text), start=1):
        b.add(block, f"image block {i}")
    if not b.parts:
        b.warnings.append("OCR found no text in the image")
    else:
        b.warnings.append("text was read by OCR; unusual fonts or blurry screenshots can cause misreadings")
    return b.done(ocr_used=True)


def _ranges(nums: list[int]) -> str:
    out, start, prev = [], nums[0], nums[0]
    for n in nums[1:] + [None]:
        if n is not None and n == prev + 1:
            prev = n
            continue
        out.append(f"{start}" if start == prev else f"{start}-{prev}")
        if n is not None:
            start = prev = n
    return ", ".join(out)
