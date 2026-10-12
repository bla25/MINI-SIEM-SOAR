
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO

WORKDIR /app

COPY collector/ ./collector/
COPY parser/ ./parser/
COPY detection/ ./detection/
COPY response/ ./response/
COPY config/ ./config/
COPY utils/ ./utils/

RUN mkdir -p /app/data /app/logs \
    && useradd --system --uid 10001 sentinel \
    && chown -R sentinel:sentinel /app

USER sentinel

CMD ["python", "-u", "collector/log_collector.py"]

