FROM python:3.12-slim

LABEL org.opencontainers.image.title="Routarr" \
      org.opencontainers.image.description="Plex/Jellyfin → Tunarr routing companion" \
      org.opencontainers.image.url="https://github.com/black7spades/routarr" \
      org.opencontainers.image.source="https://github.com/black7spades/routarr" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY main.py .

# Data volume — SQLite database lives here
VOLUME /data

EXPOSE 6942

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:6942/api/health')" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "6942"]
