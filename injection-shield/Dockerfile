# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Builder stage — compile wheel from flat-layout source
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Copy package metadata and flat-layout source files
COPY pyproject.toml ./
COPY __init__.py ./
COPY plugin.py ./
COPY config.py ./
COPY plugin.yaml ./
COPY detectors ./detectors

# Also copy any other package-level modules that setuptools includes
COPY scripts ./scripts

# Build the wheel
RUN pip install --no-cache-dir build && \
    python -m build --wheel && \
    mkdir -p /install && \
    pip install --no-cache-dir --target=/install dist/*.whl

# ---------------------------------------------------------------------------
# Runtime stage — minimal image with non-root user
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

RUN groupadd -r is && \
    useradd -r -g is -d /app -s /sbin/nologin is

WORKDIR /app

# Copy installed site-packages from builder
COPY --from=builder /install /usr/local/lib/python3.11/site-packages

# Copy plugin manifest so the runtime can introspect version
COPY --chown=is:is plugin.yaml /app/plugin.yaml

USER is

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
    CMD python -c "import injection_shield; assert injection_shield.__version__" || exit 1

LABEL org.opencontainers.image.title="injection-shield" \
      org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.source="https://github.com/dirk/injection-shield"
