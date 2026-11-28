"""Integration checks on two disposable Linux/PostgreSQL scenarios."""
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

from lab import HERE, ROLES, compose, down, migrate, project, query, up


def equal(actual, expected):
    if actual != expected:
        raise RuntimeError(f"expected {expected!r}, observed {actual!r}")


def verify_pair(primary, neighbor):
    refs = json.loads((HERE.parents[1] / "fixtures/boletas/references.json").read_text())
    up(primary)
    up(neighbor)
    migrate(primary)
    for db in ROLES:
        def app(sql):
            return query(primary, db, db, sql)

        equal(app("SHOW server_version_num"), "170007")
        equal(app("SELECT current_user || '/' || current_database()"), f"{db}/{db}")
        equal(app("SELECT rolcreatedb OR rolcreaterole OR rolsuper OR rolreplication "
                  "FROM pg_roles WHERE rolname=current_user"), "f")
        equal(app("SELECT manager_id,portfolio_id,custodian_id,administrator_id "
                  "FROM portfolio_access a JOIN portfolio p ON a.portfolio_id=p.id"),
              "\n".join(sorted("|".join((m, p, refs["portfolios"][p]["custodianId"],
                                         refs["portfolios"][p]["administratorId"]))
                               for m, rec in refs["managers"].items() for p in rec["portfolios"])))
        equal(app("SELECT id,issuer_id,asset_type FROM asset ORDER BY id"),
              "\n".join(sorted("|".join((a, rec["issuerId"], rec["assetType"]))
                               for a, rec in refs["assets"].items())))
        equal(app("SELECT id FROM counterparty ORDER BY id"), "\n".join(sorted(refs["counterparties"])))
        for other in (*ROLES, "postgres", "template1"):
            if db != other:
                query(primary, db, other, "SELECT 1", reject="permission denied for database")
        other = ROLES[(ROLES.index(db) + 1) % len(ROLES)]
        bad = compose(primary, "exec", "-T", "-u", "postgres", "db", "sh", "-ec",
                      'export PGPASSWORD="$(cat /credentials/$1/password)"; '
                      'exec psql -Xw -h db -U "$2" -d "$2" -c "SELECT 1"',
                      "sh", other, db, capture_output=True, text=True)
        if not bad.returncode or "password authentication failed" not in bad.stderr:
            raise RuntimeError("expected SCRAM rejection")
        query(primary, "postgres", db, "CREATE TABLE probe (id text PRIMARY KEY); "
              f"GRANT INSERT, SELECT ON probe TO {db};")
        app(f"BEGIN; INSERT INTO probe VALUES ('{db}'); COMMIT;")
        app("BEGIN; INSERT INTO probe VALUES ('rolled-back'); ROLLBACK;")
        query(primary, db, db, "BEGIN; INSERT INTO probe VALUES ('partial'); "
              f"INSERT INTO probe VALUES ('{db}'); COMMIT;", reject="23505")
        equal(app("SELECT id FROM probe"), db)
        # Two separate sessions contend for the same key. Exactly one insert wins.
        race = ("WITH inserted AS (INSERT INTO probe VALUES ('race') ON CONFLICT "
                "DO NOTHING RETURNING id) SELECT count(*) FROM inserted")
        with ThreadPoolExecutor(max_workers=2) as pool:
            equal(sorted(pool.map(app, [race, race])), ["0", "1"])
    print("PASS catalogs, migration replay, authenticated isolation, commit/rollback and concurrent uniqueness")
    # Recreate, not just reconnect: only volumes survive.
    compose(primary, "up", "-d", "--force-recreate", "--wait", check=True)
    for db in ROLES:
        equal(query(primary, db, db, "SELECT id FROM probe ORDER BY id"), db + "\nrace")
    down(primary)
    for kind in ("volume", "network", "container"):
        flags = ["-aq"] if kind == "container" else ["-q"]
        result = subprocess.run(["docker", kind, "ls", *flags, "--filter",
                                 "label=com.docker.compose.project=" + project(primary)],
                                check=True, text=True, capture_output=True)
        equal(result.stdout.strip(), "")
    for db in ROLES:
        equal(query(neighbor, db, db, "SELECT count(*) FROM portfolio"), "1")
    print("PASS persisted after recreation; scoped removal left second scenario available")
