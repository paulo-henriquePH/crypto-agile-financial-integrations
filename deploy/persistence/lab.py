"""Scenario-scoped Docker Compose entrypoint; requires Python 3.10+."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROLES = ("platform", "custodian", "administrator")


def project(scenario):
    if not re.fullmatch("[a-z][a-z0-9-]{0,30}", scenario):
        raise ValueError("scenario must match [a-z][a-z0-9-]{0,30}")
    return "cafi-s2-" + scenario


def compose(scenario, *args, **kwargs):
    return subprocess.run(
        ["docker", "compose", "-f", str(HERE / "compose.yaml"),
         "-p", project(scenario), *args], **kwargs)


def query(scenario, role, db, sql, reject=None):
    result = compose(scenario, "exec", "-T", "-u", "postgres", "db", "sh",
                     "/lab/connect.sh", role, db, "-qAt", "-v", f"service={db}",
                     "-v", "VERBOSITY=verbose", input=sql, capture_output=True,
                     text=True, encoding="utf-8")
    if reject:
        if result.returncode == 0 or reject not in result.stderr:
            raise RuntimeError(f"expected {reject} for {role} -> {db}")
    elif result.returncode:
        # Avoid leaking server diagnostics from credential provisioning.
        raise RuntimeError(f"psql failed ({result.returncode}): {role} -> {db}")
    return result.stdout.strip()


def migrate(scenario):
    for db in ROLES:
        # service is also passed explicitly here because maintenance uses postgres.
        query(scenario, "postgres", "postgres",
              f"\\set service {db}\n" + (HERE / "provision.sql").read_text())
        sql = """BEGIN;
            SELECT pg_advisory_xact_lock(204);
            CREATE TABLE IF NOT EXISTS schema_migration (
                name text PRIMARY KEY, checksum text NOT NULL);
            REVOKE CREATE ON SCHEMA public FROM PUBLIC;
        """
        for path in sorted((HERE / "migrations").glob("*.sql")):
            if not re.fullmatch(r"\d{3}_[a-z0-9_]+\.sql", path.name):
                raise ValueError("invalid migration name")
            body = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(body.encode()).hexdigest()
            sql += f"""
              DO $$ BEGIN IF EXISTS (SELECT FROM schema_migration
                WHERE name='{path.name}' AND checksum <> '{digest}') THEN
                RAISE EXCEPTION 'changed migration'; END IF; END $$;
              SELECT NOT EXISTS (SELECT FROM schema_migration
                WHERE name='{path.name}') AS pending \\gset
              \\if :pending
              {body}
              INSERT INTO schema_migration VALUES ('{path.name}', '{digest}');
              \\endif
            """
        query(scenario, "postgres", db, sql + "\nCOMMIT;")


def up(scenario):
    compose(scenario, "up", "-d", "--wait", "--wait-timeout", "120", check=True)
    migrate(scenario)


def down(scenario):
    compose(scenario, "down", "--volumes", check=True)


def verify():
    from verify_db import verify_pair

    scenarios = ["verify-" + uuid4().hex[:20] for _ in range(2)]
    try:
        verify_pair(*scenarios)
    finally:
        try:
            down(scenarios[0])
        finally:
            down(scenarios[1])


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "migrate", "restart", "down", "sql"):
        cmd = sub.add_parser(name)
        cmd.add_argument("scenario")
        if name == "sql":
            cmd.add_argument("role", choices=ROLES)
    sub.add_parser("verify")
    args = parser.parse_args()
    if args.command == "verify":
        verify()
        print("PASS cleanup; 0 skips")
    elif args.command == "up":
        up(args.scenario)
    elif args.command == "down":
        down(args.scenario)
    elif args.command == "migrate":
        migrate(args.scenario)
    elif args.command == "restart":
        compose(args.scenario, "restart", "db", check=True)
        compose(args.scenario, "up", "-d", "--wait", check=True)
    elif args.command == "sql":
        print(query(args.scenario, args.role, args.role, sys.stdin.read()))


if __name__ == "__main__":
    main()
