# Lean image for Mantis *web* mode only (URL scanning — no CodeQL/fuzzing).
# Build from the repository root:
#   docker build -f scan-server/Dockerfile -t mantis-web:local .
# Then run the server with USE_DOCKER=1.
FROM python:3.14.6-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt || true
COPY . .

# Drop privileges — the scan process should not run as root.
RUN useradd -m scanner && mkdir -p /out && chown scanner /out
USER scanner

ENTRYPOINT ["python3", "mantishack.py"]
CMD ["help"]
