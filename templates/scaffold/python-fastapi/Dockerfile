FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY --chown=app:app . .

USER app
EXPOSE 3000

# AppCrane sets PORT; 3000 is the fallback and must match EXPOSE.
CMD ["sh", "-c", "exec uvicorn app.main:build --factory --host 0.0.0.0 --port ${PORT:-3000}"]
