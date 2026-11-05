# Multi-stage Dockerfile for privacy-shield.
# Builds a small, non-root runtime image with Tesseract OCR support.
#
# Build:
#   docker build -t privacy-shield:latest .
# Run (example):
#   docker run --rm -e PRIVACY_SHIELD_KEY_FILE=/run/secrets/key privacy-shield:latest scan "foo@bar.com"

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata first to leverage layer caching.
COPY pyproject.toml requirements.txt ./
COPY privacy_shield.egg-info/ ./privacy_shield.egg-info/

# Install the package and all runtime dependencies into a virtual environment.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install -e "."

# Copy the actual source tree.
COPY . /build/
RUN /opt/venv/bin/pip install -e "." --no-deps

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Install Tesseract OCR + German language data required by the image preprocessor.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-deu \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the application.
RUN groupadd -r shield && useradd -r -g shield -d /app -s /sbin/nologin shield

# Bring in the virtual environment from the builder stage.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Copy the application code (editable install already points here via PYTHONPATH).
WORKDIR /app
COPY --chown=shield:shield . /app/

# Make the package importable without requiring an editable install inside the image.
ENV PYTHONPATH="/app:${PYTHONPATH}"

USER shield

# The CLI exposes a quick doctor check that is safe to run repeatedly.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD privacy-shield doctor --quick || exit 1

ENTRYPOINT ["privacy-shield"]
CMD ["doctor", "--quick"]
