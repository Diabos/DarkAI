FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium chromium-driver \
    libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir \
        torch==2.2.2+cpu \
        torchvision==0.17.2+cpu \
        -f https://download.pytorch.org/whl/torch_stable.html && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root for security
RUN useradd -m appuser \
    && mkdir -p /app/data /home/appuser/.cache/huggingface /home/appuser/.EasyOCR \
    && chown -R appuser:appuser /app /home/appuser
USER appuser

HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import sqlite3; sqlite3.connect('/app/data/crawler.db').execute('SELECT 1')" || exit 1

CMD ["python", "main.py"]