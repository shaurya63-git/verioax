"""Write the [theme] colours in .streamlit/config.toml from the design tokens in app/theme.py.

    python scripts/sync_theme.py           # update the file
    python scripts/sync_theme.py --check   # exit 1 if the file is out of date (used by the tests)

Only the keys the tokens own are rewritten; fonts, radii and the server settings stay as they are."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
import theme  # noqa: E402

CONFIG = ROOT / ".streamlit" / "config.toml"


def _toml(v) -> str:
    if isinstance(v, list):
        return "[" + ", ".join(_toml(x) for x in v) + "]"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return f'"{v}"'


def render(text: str) -> str:
    for section, values in theme.streamlit_theme().items():
        head = re.search(rf"(?m)^\[{re.escape(section)}\]\s*$", text)
        if head is None:
            text = text.rstrip("\n") + f"\n\n[{section}]\n"
            head = re.search(rf"(?m)^\[{re.escape(section)}\]\s*$", text)
        nxt = re.search(r"(?m)^\[", text[head.end():])
        end = head.end() + (nxt.start() if nxt else len(text) - head.end())
        body = text[head.end():end]
        for key, value in values.items():
            line = f"{key} = {_toml(value)}"
            pat = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
            body = pat.sub(line, body, count=1) if pat.search(body) else body.rstrip("\n") + f"\n{line}\n"
        text = text[:head.end()] + body + text[end:]
    return text


def main(argv: list[str]) -> int:
    current = CONFIG.read_text(encoding="utf-8")
    wanted = render(current)
    if "--check" in argv:
        if wanted != current:
            print(".streamlit/config.toml is out of date - run: python scripts/sync_theme.py")
            return 1
        print("theme in sync")
        return 0
    if wanted != current:
        CONFIG.write_text(wanted, encoding="utf-8")
        print("updated .streamlit/config.toml")
    else:
        print("already in sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
