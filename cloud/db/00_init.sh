#!/bin/bash
# Executado pelo container postgres na primeira subida. Senhas vêm de variáveis (arquivo .env, fora do Git).
set -e
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" <<SQL
CREATE ROLE ingest_app LOGIN PASSWORD '${INGEST_DB_PASS}';
CREATE ROLE panel_app LOGIN PASSWORD '${PANEL_DB_PASS}';
CREATE ROLE approval_app LOGIN PASSWORD '${APPROVAL_DB_PASS}';
CREATE ROLE auditor_ro LOGIN PASSWORD '${AUDITOR_DB_PASS}';
CREATE ROLE painel_legado LOGIN PASSWORD '${LEGACY_DB_PASS}' SUPERUSER;
CREATE DATABASE vila;
CREATE DATABASE vila_legado OWNER painel_legado;
SQL
for f in /docker-entrypoint-initdb.d/sql/*.sql; do psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -f "$f"; done
psql -U "$POSTGRES_USER" -d vila_legado -c "ALTER TABLE usuarios OWNER TO painel_legado; ALTER TABLE historico_acessos OWNER TO painel_legado; ALTER TABLE agendamento_bomba OWNER TO painel_legado;"
