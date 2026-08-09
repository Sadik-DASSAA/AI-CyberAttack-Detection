FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache

# Paire compatible avec les contraintes publiees par Streamlit 1.61.1.
# Streamlit 1.61.1 exige Starlette >= 0.46.0 et < 1.4.0.
# Starlette 1.3.1 est la derniere version corrective dans cet intervalle.
ARG STREAMLIT_VERSION=1.61.1
ARG STARLETTE_VERSION=1.3.1

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt

RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install -r /tmp/requirements.txt \
    && python -m pip install --upgrade --force-reinstall \
        "streamlit==${STREAMLIT_VERSION}" \
        "starlette==${STARLETTE_VERSION}" \
        "reportlab>=4.4,<5" \
        "scikit-learn==1.8.0" \
        "tornado>=6.5.2,<7" \
    && python -c "import inspect, reportlab, sklearn, starlette, streamlit; from io import BytesIO; from reportlab.pdfgen import canvas; from starlette.middleware.gzip import GZipResponder; p = inspect.signature(GZipResponder.__init__).parameters.get('thread_minimum_size'); assert p is None or p.default is not inspect.Parameter.empty, 'Starlette GZip incompatible'; b = BytesIO(); c = canvas.Canvas(b); c.drawString(20, 20, 'PDF OK'); c.save(); assert b.getvalue().startswith(b'%PDF-'); print('Versions validees : Streamlit', streamlit.__version__, '- Starlette', starlette.__version__, '- ReportLab', reportlab.Version, '- scikit-learn', sklearn.__version__)" \
    && groupadd --gid 10001 soc \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin soc \
    && mkdir -p /app/history /app/security /runtime/streamlit /tmp/.cache \
    && chown -R soc:soc /app /runtime/streamlit /tmp/.cache

COPY --chown=soc:soc api.py auth_security.py app.py data_migration.py /app/

USER 10001:10001

EXPOSE 8000 8501
