FROM node:24.20.0-slim AS node_runtime

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=180 \
    PIP_RETRIES=10 \
    WEB_PORT=8095

COPY --from=node_runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node_runtime /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && node --version \
    && npm --version

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       perl \
       ca-certificates \
       spamassassin \
       libdbd-mysql-perl \
       libbsd-resource-perl \
       libarchive-zip-perl \
       libio-string-perl \
    && (id amavis >/dev/null 2>&1 || useradd --system --home-dir /var/lib/amavis --create-home --shell /usr/sbin/nologin amavis) \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefer-binary --timeout 180 --retries 10 -r requirements.txt

COPY app /app/app
COPY local-email-intelligence-repo /app/local-email-intelligence-repo
COPY licenses /app/licenses
COPY amavisd-release-wrapper.py /usr/local/bin/amavisd-release-wrapper
RUN chmod 0755 /usr/local/bin/amavisd-release-wrapper

EXPOSE 8095

CMD ["sh","-c","exec uvicorn app.main:app --host 0.0.0.0 --port \"${WEB_PORT:-8095}\" --no-server-header"]
