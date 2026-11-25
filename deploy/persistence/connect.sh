#!/bin/sh
set -eu
role=$1
database=$2
shift 2
export LC_ALL=C
PGPASSWORD=$(cat "/credentials/$role/password")
export PGPASSWORD
exec psql -X -w -h db -U "$role" -d "$database" -v ON_ERROR_STOP=1 "$@"
