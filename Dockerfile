# ─── Simurg IDS — Dockerfile ───────────────────────────────────────────────
# Multi-stage build: slim Python runtime, runs as non-root `Simurg` user.
# No pip dependencies required — stdlib only.
#
# Build:  docker build -t simurg:latest .
# Run:    docker run -v $(pwd)/logs:/app/logs -v $(pwd)/alerts:/app/alerts simurg:latest

FROM python:3.12-slim AS runtime

LABEL maintainer="Simurg IDS"
LABEL description="Simurg IDS — Enterprise Intrusion Detection System"
LABEL version="2.0"

# Create non-root user
RUN addgroup --system Simurg \
 && adduser  --system --ingroup Simurg --no-create-home --shell /sbin/nologin Simurg

WORKDIR /app

# Copy source
COPY --chown=simurg:Simurg . .

# Create directories for runtime I/O
RUN mkdir -p /app/logs /app/alerts \
 && chown -R simurg:Simurg /app

# Switch to non-root
USER Simurg

# Health check — ensure monitor script is importable
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import log_monitor; import ingestion.parsers; print('OK')" || exit 1

# Expose UDP syslog input port
EXPOSE 5140/udp

# Default: run the full pipeline daemon
ENTRYPOINT ["python", "-u", "log_monitor.py"]
