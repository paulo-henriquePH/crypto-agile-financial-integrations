#!/bin/sh
set -eu
umask 077
for role in postgres platform custodian administrator; do
    dir=/credentials/$role
    if [ ! -f "$dir/password" ]; then
        # Never silently replace lost credentials for an initialized cluster.
        test ! -f "$PGDATA/PG_VERSION"
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$dir/new"
        test "$(wc -c < "$dir/new")" -eq 64
        chown postgres:postgres "$dir/new"
        mv "$dir/new" "$dir/password"
    fi
done
exec docker-entrypoint.sh postgres
