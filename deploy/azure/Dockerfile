FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 SECOND_SHIFT_HOME=/var/lib/second-shift
WORKDIR /opt/second-shift

COPY pyproject.toml .
COPY maverick ./maverick
COPY maverick_dashboard ./maverick_dashboard
COPY runtime/pyproject.toml runtime/README.md ./runtime/
COPY runtime/second_shift_runtime ./runtime/second_shift_runtime
RUN --mount=type=secret,id=pip_ca \
    if [ -f /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi \
    && chmod -R a+rX maverick maverick_dashboard runtime && pip install --no-cache-dir './runtime[office]' \
    && pip install --no-cache-dir '.[postgres]' 'azure-identity>=1.24,<2' 'azure-keyvault-keys>=4.11,<5' \
    && groupadd --gid 10001 secondshift \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/second-shift --no-create-home secondshift \
    && install -d -m 0700 -o secondshift -g secondshift /var/lib/second-shift

COPY --chmod=0444 deploy/azure/service.toml /opt/second-shift/service.toml
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s --start-period=30s \
    CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/livez', timeout=3).close()"]
CMD ["python", "-m", "maverick_dashboard.app", "--host", "0.0.0.0", "--port", "8000"]
