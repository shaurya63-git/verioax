"""Container health check: exit 0 when the web app or the API on this container answers."""
import sys
import urllib.request

for url in ("http://127.0.0.1:8501/_stcore/health", "http://127.0.0.1:8000/health"):
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            if resp.status == 200:
                sys.exit(0)
    except OSError:
        pass
sys.exit(1)
