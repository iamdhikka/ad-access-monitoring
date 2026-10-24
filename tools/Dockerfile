FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY adlib.py simulate.py exporter.py ./

# Jalankan sebagai user non-root
RUN useradd --uid 10001 --no-create-home app
USER app

ENV PYTHONUNBUFFERED=1 \
    PROMETHEUS_DISABLE_CREATED_SERIES=True
