# Disposable PostgreSQL 17 + pgAudit for the offline #92 security proof.
# This image is used in CI only, never for Azure or production.
FROM postgres:17-bookworm
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends postgresql-17-pgaudit \
    && rm -rf /var/lib/apt/lists/*
