#!/bin/sh
# Start PostgreSQL with its data dir on the sealed /data volume, then
# exec the drive service. /data is the per-app encrypted volume whose
# key is reconstructed from the vault constellation at boot, so the
# index is encrypted at rest under the owner's key and survives
# restarts and owner-approved upgrades.
#
# Deliberately NOT `set -e`: a Postgres hiccup must not stop the service
# from binding its port. The service starts, reports the DB state via
# its endpoints, and the failure is visible remotely instead of
# crash-looping invisibly.

export PGDATA=/data/pgdata
PGPORT=5432

# Postgres needs its runtime socket dir; the base image's entrypoint
# (which we override) normally creates it.
mkdir -p /var/run/postgresql 2>/dev/null || echo "entrypoint: mkdir /var/run/postgresql failed"
chown postgres:postgres /var/run/postgresql 2>/dev/null || echo "entrypoint: chown /var/run/postgresql failed"

mkdir -p "$PGDATA" 2>/dev/null || echo "entrypoint: mkdir $PGDATA failed"
chown -R postgres:postgres "$PGDATA" 2>/dev/null || echo "entrypoint: chown $PGDATA failed"
chmod 700 "$PGDATA" 2>/dev/null || true

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "entrypoint: initialising PostgreSQL on /data…"
  # Trust loopback only: Postgres binds 127.0.0.1 (never the host
  # network), so trusting local TCP + socket is safe with no password.
  su postgres -c "initdb -D '$PGDATA' --auth-local=trust --auth-host=trust" || echo "entrypoint: initdb failed"
fi

# Loopback only — reachable solely from inside this enclave container.
su postgres -c "pg_ctl -D '$PGDATA' -o '-c listen_addresses=127.0.0.1 -p $PGPORT' -w start" || echo "entrypoint: pg_ctl start failed"

if ! su postgres -c "psql -p $PGPORT -tAc \"SELECT 1 FROM pg_database WHERE datname='drive'\"" 2>/dev/null | grep -q 1; then
  su postgres -c "psql -p $PGPORT -c 'CREATE DATABASE drive'" || echo "entrypoint: create database failed"
fi

export DRIVE_DB_DSN="${DRIVE_DB_DSN:-postgres://postgres@127.0.0.1:5432/drive?sslmode=disable}"

: "${PORT:?PORT environment variable is required}"
echo "entrypoint: starting drive on :$PORT…"
exec drive serve
