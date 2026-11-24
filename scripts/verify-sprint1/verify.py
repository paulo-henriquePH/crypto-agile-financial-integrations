"""Inside the sandbox: run, check and summarize the Sprint 1 validators."""

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from xml.parsers import expat


TOOLS = "scripts/verify-sprint1"
LOCKS = (
    "deploy/contracts/requirements-boleta.txt",
    "contracts/vectors/json/requirements.txt",
    "deploy/contracts/requirements-xml.txt",
    "deploy/contracts/requirements-openapi.txt",
    "deploy/contracts/requirements-soap.txt",
)
REPORT = {"cases": [], "skips": 0}


class Failed(Exception):
    def __init__(self, reason, code=1):
        self.reason = reason
        self.code = code if 0 < code < 256 else 1


def require(condition, reason):
    if not condition:
        raise Failed(reason)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(name, *args, parse=None, env=None, invalid=False):
    case = {"id": name, "command": ["python", *args], "status": "failed"}
    if env:
        case["env"] = env
    REPORT["cases"].append(case)
    try:
        child = subprocess.run([sys.executable, *args], env={**os.environ, **(env or {})},
                               stdin=subprocess.DEVNULL, capture_output=True,
                               encoding="utf-8", errors="replace", timeout=180, check=False)
        case["exitCode"] = child.returncode
        if parse is not None and (child.returncode == 0 or name.startswith("unittest-")):
            case["result"] = parse(child.stdout)
            if name.startswith("unittest-"):
                REPORT["skips"] += case["result"]["skips"]
        if child.returncode != 0:
            reason = "validator-exit-nonzero"
            if (invalid and child.returncode == 1 and not child.stdout.strip()
                    and child.stderr.strip() == "S1-17: platform-ecdsa-request: signature:ECDSA-P256-SHA256"):
                reason = "mutated-expected-positive-rejected-by-EVP"
            raise Failed(reason, child.returncode)
        require(not invalid, "mutated-expected-positive-was-accepted")
        case["status"] = "passed"
    except Failed as exc:
        case["failure"] = exc.reason
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        case["failure"] = type(exc).__name__
        raise Failed(case["failure"]) from None


def one_line(expected):
    def parse(output):
        text = output.strip()
        require(re.fullmatch(expected, text) is not None, "unexpected-validator-summary")
        return text
    return parse


def inventory(output):
    observed = json.loads(output)
    manifest = read_json("deploy/spikes/versions.json")
    require(observed["diagnosticSHA256"] == sha256("spikes/environment.py"),
            "embedded-diagnostic-does-not-match-snapshot")
    require(observed["machine"] == "x86_64" and observed["python"] == manifest["python"]
            and observed["opensslLoaded"].startswith("OpenSSL " + manifest["openssl"] + " "),
            "runtime-pin-mismatch")
    return observed


def packages():
    # Validate installed versions against all wheel locks; record loaded XML ABI too.
    case = {"id": "package-lock-versions", "status": "failed"}
    REPORT["cases"].append(case)
    try:
        from lxml import etree

        pinned = {}
        for path in LOCKS:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                match = re.fullmatch(r"([\w.-]+)==(\S+)\s+(?:--hash=sha256:[a-f0-9]{64}\s*)+", line)
                require(match is not None, "unexpected-lock-syntax")
                name, version = match.groups()
                pinned[name] = importlib.metadata.version(name)
                require(pinned[name] == version, "installed-package-version-mismatch:" + name)
        case["result"] = {
            "installedPinnedVersions": pinned, "pip": importlib.metadata.version("pip"),
            "lxmlExtensionSHA256": sha256(etree.__file__),
            "libxml2Loaded": etree.LIBXML_VERSION, "libxml2Compiled": etree.LIBXML_COMPILED_VERSION,
            "libxsltLoaded": etree.LIBXSLT_VERSION, "libxsltCompiled": etree.LIBXSLT_COMPILED_VERSION,
            "expatLoaded": expat.EXPAT_VERSION,
        }
        case.update(status="passed", exitCode=0)
    except (Failed, ImportError, OSError, ValueError) as exc:
        case.update(failure=exc.reason if isinstance(exc, Failed) else type(exc).__name__, exitCode=1)
        raise


def canonical_xml(output):
    cases = read_json("contracts/vectors/xml/manifest.json")["cases"]
    expected = [f"{case['name']}: {case.get('reject', 'exact bytes and digest')}" for case in cases]
    require(len(cases) == 11 and output.splitlines() == expected, "xml-vector-results-incomplete")
    return [{"id": case["name"], "status": "passed", "result": case.get("reject", "bytes-and-digest")}
            for case in cases]


def signed_cases(directory):
    def parse(output):
        path = Path(directory)
        manifest = read_json(path / "manifest.json")
        vectors = manifest["vectors"]
        names = [Path(case["wire"]).stem for case in vectors]
        expected = [f"{name}: accepted (bytes, digest and signatures)" for name in names]
        expected.append(f"{len(names)} signed vectors; reference clock {manifest['referenceNow']}")
        signature_count = len(vectors) + sum(case["profile"] == "DUAL" for case in vectors)
        require(len(set(names)) == len(names) == 27 and signature_count == 36
                and output.splitlines() == expected, "signed-vector-results-incomplete")
        return {
            "referenceNow": manifest["referenceNow"], "messages": len(vectors), "signatures": signature_count,
            "manifestSHA256": sha256(path / "manifest.json"), "publicTrustSHA256": sha256(path / "trust.json"),
            "cases": [{"id": name, "status": "passed", "signedBytesSHA256": case["sha256"],
                       "wireSHA256": sha256(path / case["wire"])} for name, case in zip(names, vectors)],
        }
    return parse


def jcs_cases():
    # Link the report to the actual successful subtests, not merely the manifest.
    suite = next(case["result"] for case in REPORT["cases"] if case["id"] == "unittest-all")
    method = suite["cases"]["test_canonical_json.CanonicalJsonTests.test_static_vectors"]
    vectors = read_json("contracts/vectors/json/manifest.json")["cases"]
    require(method["status"] == "passed" and len(vectors) == 12
            and method["subcases"] == ["passed"] * len(vectors), "jcs-vector-results-incomplete")
    suite["jcsCases"] = [{"id": row["name"], "status": "passed",
                         "result": "bytes-and-digest" if row["valid"] else "rejected"}
                        for row in vectors]


def contracts(invalid):
    run("runtime-inventory", "/opt/cafi/environment.py", parse=inventory)
    static = "contracts/vectors/signed/corpus"
    verifier = "tests/contracts/verify_signed_vectors.py"
    if invalid:
        run("signed-static", verifier, parse=signed_cases(static))
        run("signed-invalid", verifier, "--invalid", invalid=True)
        return
    run("pip-check", "-m", "pip", "check", parse=one_line(r"No broken requirements found\."))
    packages()
    run("boleta-schema", "tests/contracts/check_boleta_schema.py",
        parse=one_line(r"schema e boleta válidos"))
    run("events-schema", "tests/contracts/check_events_schema.py",
        parse=one_line(r"metaschema e \d+ eventos válidos aceitos; \d+ inválidos rejeitados"))
    run("messages-schema", "tests/contracts/check_messages_schema.py",
        parse=one_line(r"3 metaschemas; \d+ mensagens e requisições associadas verificadas; data impossível rejeitada"))
    run("platform-openapi", "tests/contracts/check_platform_openapi.py",
        parse=one_line(r"OpenAPI 3\.1 validado; \d+ exemplos e referências locais verificados; assinaturas ilustrativas"))
    run("custodian-openapi", "tests/contracts/check_custodian_openapi.py",
        parse=one_line(r"OpenAPI custodian: 8 examples, references and remote history validated; signatures illustrative"))
    run("administrator-wsdl-xsd-zeep", "tests/contracts/check_administrator_soap.py",
        parse=one_line(r"SOAP: WSDL client, local XSD and 5 examples; signatures illustrative"))
    run("unittest-all", f"{TOOLS}/unit_cases.py", "test*.py", "69", parse=json.loads)
    jcs_cases()
    run("canonical-xml", "tests/contracts/canonical_xml.py", parse=canonical_xml)
    run("signed-static", verifier, parse=signed_cases(static))
    fresh = "/tmp/fresh"
    run("signed-generate", "contracts/vectors/signed/generate.py", "--out", fresh,
        parse=one_line(r"27 freshly signed vectors verified with public keys only"))
    run("signed-fresh", verifier, "--corpus", fresh, "--trust", fresh + "/trust.json",
        parse=signed_cases(fresh))
    run("unittest-fresh-signed", f"{TOOLS}/unit_cases.py", "test_signed_vectors.py", "15",
        env={"CAFI_SIGNED_TEST_CORPUS": fresh}, parse=json.loads)


def signature(output, name):
    observed = json.loads(output)
    expected = {"original": True, "altered_payload": False, "altered_signature": False, "different_key": False}
    if name == "ml-dsa":
        expected["different_context"] = False
    require(observed["cases"] == expected, "signature-results-incomplete")
    return observed


def tls(output, hybrid):
    observed = json.loads(output)
    cases = observed["cases"]
    positive = {"trusted_peers", "trusted_peers_second_connection"}
    negative = {"wrong_server_name", "untrusted_server", "untrusted_client",
                "missing_client_certificate", "wrong_client_name"}
    incompatible = "x25519_client_to_hybrid_only_server"
    if hybrid:
        negative.add(incompatible)
    require(cases.keys() == positive | negative, "tls-results-incomplete")
    group = "x25519mlkem768" if hybrid else "x25519"
    for name in positive:
        case = cases[name]
        require(case["accepted"] is True and case["acknowledged"] is True
                and all(case[side]["group"].casefold() == group for side in ("client", "server")),
                "required-tls-group-not-observed")
    for name in negative:
        case = cases[name]
        require(case["accepted"] is False and case["acknowledged"] is False, "tls-negative-accepted")
    if hybrid:
        require(cases[incompatible]["serverHandshake"]["reason"] == "no suitable key share",
                "missing-hybrid-incompatibility")
    return observed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("contracts", "invalid", "ecdsa", "ml-dsa",
                                         "tls-x25519", "tls-hybrid-1", "tls-hybrid-2"))
    mode = parser.parse_args().mode
    try:
        if mode in {"contracts", "invalid"}:
            contracts(mode == "invalid")
        elif mode in {"ecdsa", "ml-dsa"}:
            run(mode, f"spikes/signatures/{mode}/proof.py", parse=lambda out: signature(out, mode))
        else:
            hybrid = mode != "tls-x25519"
            run(mode, "spikes/tls/proof.py", *(("--hybrid",) if hybrid else ()),
                parse=lambda out: tls(out, hybrid))
        REPORT["exitCode"] = 0
    except Failed as exc:
        REPORT.update(exitCode=exc.code, failure=exc.reason)
    except (ImportError, OSError, ValueError, KeyError, TypeError) as exc:
        REPORT.update(exitCode=1, failure=type(exc).__name__)
    print(json.dumps(REPORT, ensure_ascii=True))
    return REPORT["exitCode"]


if __name__ == "__main__":
    sys.exit(main())
