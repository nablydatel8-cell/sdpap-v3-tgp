FROM python:3.12-slim

# Создание системной рабочей директории и изоляция пользователя
WORKDIR /app

RUN groupadd -r sdpap && useradd -r -g sdpap -d /app -s /sbin/nologin sdpap \
    && mkdir -p /app/data \
    && chown -R sdpap:sdpap /app

COPY sdpap_v3_production.py /app/
COPY sdpap_cli.py /app/
COPY test_suite_full.py /app/

# Переключение на non-root пользователя
USER sdpap

# Переменные среды
ENV PYTHONUNBUFFERED=1 \
    SDPAP_DB_PATH=/app/data/sdpap_kernel.db

# Автоматический периодический аудит целостности БД каждые 30 сек
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 /app/sdpap_cli.py --db /app/data/sdpap_kernel.db audit || exit 1

ENTRYPOINT ["python3", "/app/sdpap_cli.py", "--db", "/app/data/sdpap_kernel.db"]
CMD ["audit"]
