FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DECOY_HOST=0.0.0.0 \
    DECOY_PORT=8080 \
    DECOY_LOG_DIR=/app/logs

# No extra packages: just an unprivileged user and the two source files.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin decoy \
    && mkdir -p /app/logs \
    && chown 10001:10001 /app/logs

WORKDIR /app
COPY config.py trap.py ./

USER 10001:10001
EXPOSE 8080
CMD ["python", "trap.py"]
