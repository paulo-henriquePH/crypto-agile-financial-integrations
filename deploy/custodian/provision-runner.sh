#!/bin/sh
# Run as the Docker operator, inside the scenario's PostgreSQL container.
set -eu
umask 077
dir=/credentials/custodian_runner
if [ ! -f "$dir/password" ]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$dir/new"
    test "$(wc -c < "$dir/new")" -eq 64
    chown postgres:postgres "$dir/new"
    mv "$dir/new" "$dir/password"
fi
sh /lab/connect.sh postgres custodian -q <<'SQL'
DO $$
BEGIN
    EXECUTE format('ALTER ROLE custodian_runner LOGIN PASSWORD %L',
        pg_read_file('/credentials/custodian_runner/password'));
END $$;
SQL
