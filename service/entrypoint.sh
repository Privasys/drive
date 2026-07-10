#!/bin/sh
# Start PostgreSQL with its data dir on the sealed /data volume, then
# exec the drive service. /data is the per-app encrypted volume whose
# key is reconstructed from the vault constellation at boot, so the
# index is encrypted at rest under the owner's key and survives
# restarts and owner-approved upgrades.
#
# Postgres listens on a UNIX SOCKET on /data ONLY — never TCP. On the
# platform, container apps share the host network namespace, so a TCP
# loopback listener (127.0.0.1:5432) would be reachable by any other
# co-located app and two drive instances would collide on the same
# port + share an index. A socket under the per-app LUKS /data volume
# is private to this app: co-tenants share the netns but not the mount,
# so they cannot reach it.
#
# Deliberately NOT `set -e`: a Postgres hiccup must not stop the service
# from binding its port. The service starts, reports the DB state via
# its endpoints, and the failure is visible remotely instead of
# crash-looping invisibly.

export PGDATA=/data/pgdata
PGSOCK=/data/pgsock

# The socket dir lives on the per-app encrypted volume, so it is not
# reachable by co-located apps sharing the host network namespace.
mkdir -p "$PGSOCK" 2>/dev/null || echo "entrypoint: mkdir $PGSOCK failed"
chown postgres:postgres "$PGSOCK" 2>/dev/null || echo "entrypoint: chown $PGSOCK failed"
chmod 700 "$PGSOCK" 2>/dev/null || true

mkdir -p "$PGDATA" 2>/dev/null || echo "entrypoint: mkdir $PGDATA failed"
chown -R postgres:postgres "$PGDATA" 2>/dev/null || echo "entrypoint: chown $PGDATA failed"
chmod 700 "$PGDATA" 2>/dev/null || true

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "entrypoint: initialising PostgreSQL on /data…"
  # No TCP is ever opened; local socket connections trust-auth (the
  # socket dir is private to this app's volume).
  su postgres -c "initdb -D '$PGDATA' --auth-local=trust --auth-host=reject" || echo "entrypoint: initdb failed"
fi

# Socket only, no TCP listener at all (listen_addresses='').
su postgres -c "pg_ctl -D '$PGDATA' -o \"-c listen_addresses='' -c unix_socket_directories=$PGSOCK\" -w start" || echo "entrypoint: pg_ctl start failed"

if ! su postgres -c "psql -h '$PGSOCK' -tAc \"SELECT 1 FROM pg_database WHERE datname='drive'\"" 2>/dev/null | grep -q 1; then
  su postgres -c "psql -h '$PGSOCK' -c 'CREATE DATABASE drive'" || echo "entrypoint: create database failed"
fi

# pgx reads the socket directory from the host= query parameter.
export DRIVE_DB_DSN="${DRIVE_DB_DSN:-postgres:///drive?host=$PGSOCK&sslmode=disable}"

: "${PORT:?PORT environment variable is required}"
echo "entrypoint: starting drive on :$PORT…"
exec drive serve
