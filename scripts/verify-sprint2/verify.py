"""Fail-closed S2-14 runner. Run from any directory with Python >= 3.10.

The subprocesses own their ephemeral Compose projects; this process never handles
private keys or stores raw service output. A scenario is accepted only if its
assertions complete, its witness is present, and its suite reports zero skips.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
from tempfile import gettempdir
from time import monotonic
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
CASES = {
    "platform": ("deploy/platform/lab.py", "verify", ()),
    "settlement": ("deploy/custodian/verify_settlement.py", None, ()),
    "custody": ("deploy/platform/verify_custody.py", None,
                ("acceptance", "rejection", "defensive", "receipt-rollback", "receipt-race")),
    "recovery": ("deploy/platform/verify_recovery.py", None,
                 ("outbox", "lost-reply", "killed", "expired", "gap-closed", "gap-open",
                  "unavailable", "disallowed", "known-receipt", "migration", "write-expiry")),
    "administrator": ("deploy/platform/verify_administrator.py", None,
                      ("rollback-outage", "lost-reply", "rejection", "insufficient",
                       "defensive", "exhausted", "legacy")),
    "reconciliation": ("scripts/verify-sprint2/links.py", None,
                       ("missing", "divergent", "forbidden")),
}
TLS = ("TLSv1.3", "X25519", "TLS_AES_256_GCM_SHA384")
SAFE_FIELDS = ("scenario", "operationId", "history", "apiStatuses", "differences",
               "debitsAndCredits", "entries", "reason", "rejectionOrigin", "rejected",
               "financialUnchanged", "plannedDate", "effectiveDate",
               "submitMessageId", "queryMessageIds", "ackMessageId",
               "tls", "protocol", "group", "ciphersuite", "policyVersion",
               "keyId", "signatureProfile", "nonRetryableMode",
               "acceptedAbsence", "blockedAfter", "resolved", "submits",
               "migratedBlockedWithoutWire")


def command(argv, *, timeout=30, env=None):
    if argv[0] == "docker" and env and os.name == "nt":
        candidate = Path(env.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"
        if candidate.is_file() and not shutil.which("docker"):
            argv = [str(candidate), *argv[1:]]
    flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {
        "start_new_session": True}
    proc = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace", **flags)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return 124, "", ""


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def git_state():
    rc, head, _ = command(["git", "rev-parse", "HEAD"])
    need(rc == 0, "git revision unavailable")
    rc, status, _ = command(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    need(rc == 0, "git status unavailable")
    # Hash the status, not paths from a potentially sensitive working tree.
    import hashlib
    sources = ["scripts/verify-sprint2/verify.py", "scripts/verify-sprint2/links.py",
               "scripts/verify-sprint2/test_verify.py", "deploy/persistence/compose.yaml",
               *(data[0] for data in CASES.values())]
    return {"revision": head.strip(), "treeDirty": bool(status),
            "statusSha256": hashlib.sha256(status.encode()).hexdigest(),
            "sourceSha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                             for path in dict.fromkeys(sources)}}


def witness(text, expected):
    rows = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and item.get("scenario") in expected:
            rows.append(item)
    names = [r["scenario"] for r in rows]
    multiplicity = {name: {"disallowed": 5, "migration": 3}.get(name, 1)
                    for name in expected}
    need(all(names.count(name) == count for name, count in multiplicity.items())
         and set(names) == set(expected),
          "missing/duplicate scenario witness")
    if "disallowed" in multiplicity:
        need({r.get("nonRetryableMode") for r in rows if r["scenario"] == "disallowed"} ==
             {"unsigned", "wrong-correlation", "bad-signature", "schema", "forbidden"},
             "missing non-retryable negative")
    if "migration" in multiplicity:
        migrated = [r for r in rows if r["scenario"] == "migration"]
        need(len({r["operationId"] for r in migrated}) == 3
             and sum(bool(r.get("migratedBlockedWithoutWire")) for r in migrated) == 1,
             "missing legacy migration branch")
    for row in rows:
        need(bool(row.get("operationId")) and bool(row.get("history")),
             "missing operation/history witness")
        for key in ("tls", "protocol"):
            if key in row:
                need(row[key] == TLS[0], "TLS protocol mismatch")
        if "group" in row:
            need(row["group"].upper() == TLS[1], "TLS group mismatch")
        if "ciphersuite" in row:
            need(row["ciphersuite"] == TLS[2], "TLS suite mismatch")
    sanitized = []
    for row in rows:
        item = dict({key: row[key] for key in SAFE_FIELDS if key in row}, exit=0)
        for origin, fields in (
            ("wire", ("action", "correlationId", "realStatus", "tls", "group",
                      "ciphersuite", "verifyCode", "mode")),
            ("ledger", ("action", "request", "response", "outcome", "authority",
                        "code", "delay"))):
            if origin in row:
                need(isinstance(row[origin], list), "invalid structured witness")
                item[origin] = [dict({key: event[key] for key in fields if key in event},
                                     sequence=index) for index, event in enumerate(row[origin], 1)]
        sanitized.append(item)
    return sanitized


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo-only", action="store_true",
                        help="run only the full real C1 API/REST/SOAP/reconciliation scenario; not sprint acceptance")
    parser.add_argument("--inject-failure", action="store_true",
                        help="prove fail-closed exit without starting Docker (not an acceptance run)")
    parser.add_argument("--report", type=Path, help="sanitized report destination outside the checkout")
    args = parser.parse_args()
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "assertions disabled")
    state = git_state()
    report = {"task": "S2-14", "at": datetime.now(timezone.utc).isoformat(),
              "git": state, "environment": {"hostPython": sys.version.split()[0],
              "platform": sys.platform}, "parameters": {"tls": TLS, "policyVersion": 1,
              "signature": "ECDSA-P256-SHA256", "financialCalendar": "weekdays; no holidays",
              "scenarioTimeoutSeconds": 1800, "mode": "demo" if args.demo_only else "suite"},
              "scenarios": [], "result": "FAILED"}
    if args.report:
        dest = args.report.resolve()
        need(not dest.is_relative_to(ROOT), "report must be outside checkout")
    else:
        preferred = Path(os.environ.get("LOCALAPPDATA", "")) / "Temp/opencode"
        dest = (preferred if preferred.is_dir() else Path(gettempdir())) / f"cafi-s2-14-{uuid4().hex}.json"
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONOPTIMIZE", None)
    docker = shutil.which("docker")
    if not docker and os.name == "nt":
        candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin"
        if (candidate / "docker.exe").is_file():
            env["PATH"] = str(candidate) + os.pathsep + env.get("PATH", "")
            docker = str(candidate / "docker.exe")
    failure = None
    try:
        if args.inject_failure:
            raise ValueError("injected failure: mandatory scenario not executed")
        need(bool(docker), "Docker executable unavailable")
        rc, out, _ = command(["docker", "image", "inspect", "cafi-transport:s2-03",
                              "--format", "{{.Id}}"], env=env)
        need(rc == 0 and out.strip().startswith("sha256:"), "fixed transport base image unavailable")
        report["environment"]["transportImage"] = out.strip()
        versions = ("import json,sys,ssl,importlib.metadata as m;"
                    "print(json.dumps(dict(python=sys.version.split()[0],openssl=ssl.OPENSSL_VERSION,"
                    "h11=m.version('h11'),lxml=m.version('lxml'),"
                    "rfc8785=m.version('rfc8785'))))")
        rc, out, _ = command(["docker", "run", "--rm", "--network", "none",
                              "--platform", "linux/amd64", "cafi-transport:s2-03",
                              "python", "-c", versions], timeout=90, env=env)
        need(rc == 0, "unable to observe fixed runtime versions")
        report["environment"]["serviceStack"] = json.loads(out)
        pin = re.search(r"image:\s*(postgres:17\.7-bookworm@sha256:[0-9a-f]{64})\b",
                        (ROOT / "deploy/persistence/compose.yaml").read_text(encoding="utf-8"))
        need(pin is not None, "PostgreSQL 17.7 pinned image missing")
        report["environment"]["postgresConfigured"] = pin.group(1)
        for key, argv in (("docker", ["docker", "info", "--format", "{{.ServerVersion}}"]),
                          ("compose", ["docker", "compose", "version", "--short"])):
            rc, out, _ = command(argv, env=env)
            need(rc == 0 and out.strip(), "Docker Engine/Compose unavailable")
            report["environment"][key] = out.strip()
        selected = ("reconciliation",) if args.demo_only else tuple(CASES)
        for label in selected:
            path, action, expected = CASES[label]
            argv = [sys.executable, "-B", path, *([action] if action else [])]
            started = monotonic()
            rc, out, err = command(argv, timeout=1800, env=env)
            item = {"suite": label, "command": argv[1:], "exit": rc,
                    "elapsedSeconds": round(monotonic() - started, 3), "result": "FAILED"}
            report["scenarios"].append(item)
            need(rc == 0, f"{label}: subprocess exit {rc} (timeout=124)")
            need(not re.search(r"\b(?:skipped|xfail|xpass)\b", out + err, re.I),
                 f"{label}: skipped tests")
            if expected:
                item["witnesses"] = witness(out, expected)
                need(re.search(rf"PASS S2-\d+: {len(expected)} PostgreSQL/mTLS scenarios, 0 skips",
                               out) is not None, f"{label}: missing complete-suite receipt")
                if label == "reconciliation":
                    by_name = {row["scenario"]: row for row in item["witnesses"]}
                    need(by_name["missing"].get("apiStatuses", [])[-1:] == ["MATCHED"]
                         and by_name["missing"]["history"][-1] == "SETTLED"
                         and by_name["divergent"]["history"][-1] == "SETTLED"
                         and bool(by_name["divergent"].get("differences")),
                         "reconciliation: SETTLED/MATCHED/DIVERGENT witness missing")
                    link_rows = []
                    for line in out.splitlines():
                        try:
                            row = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(row, dict) and row.get("scenario") == "tls-links":
                            link_rows.append(row)
                    need(len(link_rows) == 1 and
                         link_rows[0].get("operationId") == by_name["missing"]["operationId"],
                         "missing same-operation three-link TLS witness")
                    link = link_rows[0]
                    for name, peer in (("managerToPlatform", "platform.cafi.test"),
                                       ("platformToCustodian", "custodian.cafi.test"),
                                       ("platformToAdministrator", "administrator.cafi.test")):
                        obs = link.get(name, {})
                        need((obs.get("protocol"), str(obs.get("group", "")).upper(),
                              obs.get("ciphersuite"), obs.get("peerDnsSan"),
                              obs.get("verifyCode"), obs.get("peerKeyType"),
                              obs.get("peerKeyCurve"), obs.get("peerCertificateSignature"),
                              obs.get("verifiedChainLength"), obs.get("sessionReused"),
                              obs.get("sessionHasTicket"), obs.get("sessionResumable"),
                              obs.get("earlyDataStatus")) == (
                                  *TLS, peer, 0, "EC", "prime256v1",
                                  "ecdsa-with-SHA256", 2, False, False, False,
                                  "SSL_EARLY_DATA_NOT_SENT"),
                             f"invalid C1 TLS observation: {name}")
                    need(link.get("signatureProfile") == "ECDSA"
                         and link.get("policyVersion") == 1
                         and link.get("responseKeyIds") == {
                             "managerToPlatform": "PLATFORM-0",
                             "platformToCustodian": "CUSTODIANTE-GAMA-0",
                             "platformToAdministrator": "ADMINISTRADOR-DELTA-0"}
                         and all(link.get("serverLogsChecked", {}).get(k, 0) > 0
                                 for k in ("platform", "custodian", "administrator")),
                         "missing C1 signed server observations")
                    item["tlsLinks"] = {key: link[key] for key in
                                        ("operationId", "managerToPlatform",
                                         "platformToCustodian", "platformToAdministrator",
                                         "serverLogsChecked", "signatureProfile",
                                         "policyVersion", "responseKeyIds")}
                if label == "custody":
                    by_name = {row["scenario"]: row for row in item["witnesses"]}
                    need(all(by_name["acceptance"].get(k) == value for k, value in
                             (("tls", TLS[0]), ("ciphersuite", TLS[2]), ("debitsAndCredits", 2)))
                         and by_name["acceptance"].get("group", "").upper() == TLS[1],
                         "custody: C1/financial witness missing")
            elif label == "settlement":
                need(all(f"PASS {name}" in out for name in
                         ("acceptance:", "rejection:", "insufficient cash:"))
                     and "PASS S2-08: 3 PostgreSQL/mTLS scenarios, 0 skips" in out,
                     "settlement: missing scenario receipt")
                item["witnesses"] = [{"scenario": name, "exit": 0} for name in
                                     ("acceptance", "rejection", "insufficient")]
            else:
                need("0 skips" in out, f"{label}: missing no-skip receipt")
            item["result"] = "PASSED"
        if not args.demo_only:
            # This is a separate adapter-boundary test, not a replacement for the live links.
            started = monotonic()
            rc, out, err = command(["powershell", "-NoProfile", "-File",
                                    "scripts/verify-c1/verify.ps1"], timeout=300, env=env)
            item = {"suite": "parser-and-identity", "exit": rc,
                    "elapsedSeconds": round(monotonic() - started, 3), "result": "FAILED"}
            report["scenarios"].append(item)
            need(rc == 0 and re.search(r"Ran [1-9]\d* tests", err + out)
                 and not re.search(r"skipped|expected failure", err + out, re.I),
                 "parser/identity tests failed, skipped or not executed")
            item["result"] = "PASSED"
        report["result"] = "DEMO_ONLY" if args.demo_only else "PASSED"
    except (ValueError, OSError) as exc:
        failure = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        report["diagnostic"] = failure
    finally:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"S2-14 {report['result']}; report: {dest}")
        if failure:
            print(f"BLOCKED: {failure}", file=sys.stderr)
    return 0 if report["result"] in ("PASSED", "DEMO_ONLY") else 1


if __name__ == "__main__":
    sys.exit(main())
