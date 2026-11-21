# syntax=docker/dockerfile:1.7
# AIPISH backend (FastAPI). P5i.
#
# Image contents: Python runtime + pinned dependencies + application code + the SYNTHETIC demo fixtures.
# NOT included: secrets/.env, trained models (mounted read-only at /models), datasets, databases.
#
# WITH_ML=1 (default) installs the optional ML stack (scikit-learn, XGBoost, SHAP, transformers) with
# CPU-only PyTorch from the PyTorch CPU index (~0.6 GB instead of ~2.5 GB of CUDA wheels). The models
# themselves are mounted at runtime; without them the API reports ML as "unavailable", as before.
# WITH_ML=0 builds a ~0.3 GB rules-only image.

ARG PYTHON_IMAGE=python:3.13.18-slim-trixie

FROM ${PYTHON_IMAGE} AS deps
ARG WITH_ML=1
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /build
COPY requirements.txt requirements-ml.txt constraints.txt ./
RUN pip install -r requirements.txt -c constraints.txt \
 && if [ "$WITH_ML" = "1" ]; then \
      pip install --index-url https://download.pytorch.org/whl/cpu "torch==$(grep -i '^torch==' constraints.txt | cut -d= -f3)" \
      && pip install -r requirements-ml.txt -c constraints.txt ; \
    fi \
 && find /opt/venv -name '__pycache__' -prune -exec rm -rf {} +

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="aipish-backend" \
      org.opencontainers.image.description="AIPISH email forensics API" \
      org.opencontainers.image.source="https://github.com/vedan1turkar/AIPISH"
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/opt/venv/bin:$PATH \
    APP_ENV=production \
    APP_ENV_FILE=/nonexistent/.env \
    AIPISH_MODEL_DIR=/models/aipish-email-v1 \
    AIPISH_DEMO_CREDENTIALS_FILE=/app/var/demo/credentials \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1
RUN groupadd --system --gid 10001 aipish \
 && useradd --system --uid 10001 --gid aipish --home-dir /app --shell /usr/sbin/nologin aipish
COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root app ./app
COPY --chown=root:root tests/fixtures/demo ./tests/fixtures/demo
COPY --chown=root:root --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN mkdir -p /app/var/demo /app/db && chown -R aipish:aipish /app/var /app/db
USER aipish
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/ready', timeout=4).status == 200 else 1)"
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
