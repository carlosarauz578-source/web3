FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
ENV AEGIS_DB_PATH=/data/aegis.db
RUN useradd --create-home --uid 10001 appuser && mkdir -p /data && chown appuser:appuser /data
COPY pyproject.toml README.md ./
COPY app ./app
RUN python -m pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir .
USER appuser
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
