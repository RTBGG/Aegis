#!/bin/bash
# Postgres first-init hook: provision the PowerDNS role/database and load its
# gpgsql schema. Runs once when the data volume is empty.
set -euo pipefail

: "${PDNS_DB_NAME:=pdns}"
: "${PDNS_DB_USER:=pdns}"
: "${PDNS_DB_PASSWORD:=pdns}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE ROLE ${PDNS_DB_USER} LOGIN PASSWORD '${PDNS_DB_PASSWORD}';
	CREATE DATABASE ${PDNS_DB_NAME} OWNER ${PDNS_DB_USER};
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$PDNS_DB_NAME" -f /pdns-schema.sql

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$PDNS_DB_NAME" <<-EOSQL
	GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ${PDNS_DB_USER};
	GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ${PDNS_DB_USER};
	ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ${PDNS_DB_USER};
EOSQL

echo "PowerDNS database '${PDNS_DB_NAME}' initialised."
