# =============================================================================
# Dockerfile — blockchain-cryptography-python
# Author: Fidel Mehra
#
# Multi-stage build:
#   Stage 1 (builder) — install dependencies in a virtual environment
#   Stage 2 (runtime) — copy only the venv and app code; run as non-root
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install system libraries needed to compile cryptographic C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create an isolated virtual environment
RUN python -m venv /build/venv
ENV PATH="/build/venv/bin:$PATH"

# Upgrade pip / wheel first for speed
RUN pip install --upgrade pip wheel

# Install Python dependencies (pinned via requirements.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL maintainer="Fidel Mehra"
LABEL description="Blockchain Cryptography Python — FastAPI node"
LABEL version="1.0.0"

# Security: run as a non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /build/venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy application source
COPY src/ ./src/

# Ensure Python finds the package
ENV PYTHONPATH="/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
RUN chown -R appuser:appgroup /app
USER appuser

# Expose the FastAPI port
EXPOSE 8000

# Health check (optional but recommended)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/').read()"

# Launch with uvicorn
CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
