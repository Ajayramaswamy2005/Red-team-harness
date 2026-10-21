# Automated Red-Team Harness — application image
FROM python:3.11-slim

# Don't buffer stdout/stderr; no .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps: curl is used by the container healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies + the project itself.
# Copy the whole project first (setuptools needs the package dirs to build),
# then install. Dependencies are declared in pyproject.toml.
COPY . .
RUN pip install --upgrade pip && pip install .

# Run as a non-root user.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Tables are created automatically on startup (see the FastAPI lifespan handler).
CMD ["uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
