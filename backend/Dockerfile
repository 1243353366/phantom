FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHANTOM_HOME=/data

WORKDIR /app

COPY backend/pyproject.toml ./backend/pyproject.toml
COPY README.md ./
COPY backend/phantom ./backend/phantom
RUN pip install --no-cache-dir -e ./backend

# Run as an unprivileged user: the app reads other people's contact files and
# writes a database of who touched what. It does not need root for either.
RUN useradd --create-home --uid 10001 phantom \
 && mkdir -p /data && chown -R phantom:phantom /data /app
USER phantom

WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "phantom.main:app", "--host", "0.0.0.0", "--port", "8000"]
