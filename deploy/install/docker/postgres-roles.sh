#!/bin/sh
# Creates the database roles Hodor connects as, the first time the PostgreSQL container fills its volume.
# The owner of the schema, hodor_owner, is created by the image itself.
#
# The passwords come from the environment of the container, which Compose fills from `.env`. They are given
# to psql as variables and written with :'name', so that a password holding a quote stays a password.
set -e

psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set server_password="$HODOR_SERVER_DATABASE_PASSWORD" \
  --set worker_password="$HODOR_WORKER_DATABASE_PASSWORD" <<'SQL'
-- The two groups the migrations grant to. Neither can log in.
CREATE ROLE hodor_app NOLOGIN;
CREATE ROLE hodor_platform NOLOGIN;

-- The server only ever acts inside one tenant.
CREATE ROLE hodor_server LOGIN PASSWORD :'server_password' IN ROLE hodor_app;

-- The worker finds work across tenants, then handles it inside one.
CREATE ROLE hodor_worker LOGIN PASSWORD :'worker_password' IN ROLE hodor_app;
CREATE ROLE hodor_worker_platform LOGIN PASSWORD :'worker_password' IN ROLE hodor_platform;
SQL
