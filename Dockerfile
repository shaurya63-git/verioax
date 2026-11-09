# Verioax - one image for both the web app (default) and the REST API.
#   docker build -t verioax .
#   docker run --rm -p 127.0.0.1:8501:8501 verioax                       # web app
#   docker run --rm -p 127.0.0.1:8000:8000 verioax \
#       uvicorn api.main:app --host 0.0.0.0 --port 8000                         # API
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TRUSTGUARD_DATA_DIR=/app/data/runtime

# Tesseract (English + Hindi) for OCR of images inside PDFs / Word files; DejaVu fonts for PDF reports.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng tesseract-ocr-hin fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN useradd --create-home --uid 10001 trustguard \
 && mkdir -p /app/data/runtime \
 && chown -R trustguard:trustguard /app/data/runtime
USER trustguard

EXPOSE 8501 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["python", "scripts/healthcheck.py"]

CMD ["streamlit", "run", "app/streamlit_app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true", "--browser.gatherUsageStats=false"]
