"""S2-14 augmentation of the S2-13 real flow: observe all three live C1 links."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "deploy/platform"))
import verify_reconciliation as integrated

TLS = ("TLSv1.3", "X25519", "TLS_AES_256_GCM_SHA384")
original_once = integrated.Flow.once
original_evidence = integrated.Flow.evidence

# Executed by the real manager container; the same signed API client validates
# the response while this wrapper records the trustworthy client TLS observation.
MANAGER_PROBE = """
from contextlib import contextmanager
import json, sys
sys.path.insert(0, '/repo/tests/platform')
import exchanges as client
from c1.runtime import connect as real_connect
observed = []
@contextmanager
def witness(*args, **kwargs):
    with real_connect(*args, **kwargs) as session:
        observed.append(session.observation)
        yield session
client.connect = witness
status, operation, payload, _ = client.exchange(op=sys.argv[1])
assert (status, operation, payload['state'], payload['reconciliationStatus']) == (
    200, sys.argv[1], 'SETTLED', 'MATCHED')
assert len(observed) == 1
print(json.dumps(observed[0]))
"""

CUSTODY_PROBE = """
import json, sys
from pathlib import Path
from services.platform.custody import Client
client = Client(Path('/custody-identity'))
with client.connection() as session:
    route, wire, request = client.prepare(
        session, sys.argv[1], None, lambda _: ('GESTORA-ALFA', 'FUNDO-ALFA'))
    response = client.send_verified(session, route, wire, request)
    assert response.status == 200 and response.content['payload']['state'] == 'SETTLED'
    print(json.dumps(session.observation))
"""

SOAP_PROBE = """
import json, sys
from services.platform.administrator import Client
response = Client().exchange(sys.argv[1], ('GESTORA-ALFA', 'FUNDO-ALFA'))
assert response.status == 200 and response.content['payload']['state'] == 'SETTLED'
print(json.dumps(response.observation))
"""


def checked(observed, peer):
    assert (observed["protocol"], observed["group"].upper(),
            observed["ciphersuite"], observed["peerDnsSan"],
            observed["verifyCode"]) == (*TLS, peer, 0)
    assert (observed["peerKeyType"], observed["peerKeyCurve"],
            observed["peerCertificateSignature"], observed["verifiedChainLength"],
            observed["sessionReused"], observed["sessionHasTicket"],
            observed["sessionResumable"], observed["earlyDataStatus"]) == (
                "EC", "prime256v1", "ecdsa-with-SHA256", 2,
                False, False, False, "SSL_EARLY_DATA_NOT_SENT")
    return {key: observed[key] for key in
            ("protocol", "group", "ciphersuite", "peerDnsSan", "verifyCode",
             "peerKeyType", "peerKeyCurve", "peerCertificateSignature",
             "verifiedChainLength", "sessionReused", "sessionHasTicket",
             "sessionResumable", "earlyDataStatus")}


def once(self, *args, **kwargs):
    rows = original_once(self, *args, **kwargs)
    if self.name == "missing":
        service = kwargs.get("service", "worker")
        for row in rows:
            if all(k in row for k in
                   ("protocol", "group", "ciphersuite", "peerDnsSan", "verifyCode")):
                self.link_observations.setdefault(service, []).append(row)
    return rows


def evidence(self, states, **values):
    if self.name == "missing":
        manager = json.loads(self.compose(
            "run", "--rm", "-T", "manager", "python", "-c", MANAGER_PROBE,
            self.operation, capture=True))
        manager = checked(manager, "platform.cafi.test")
        administrator_worker = self.link_observations.get("administrator-worker", [])
        assert administrator_worker
        custody = json.loads(self.compose(
            "run", "--rm", "-T", "--no-deps", "--entrypoint", "python",
            "worker", "-c", CUSTODY_PROBE, self.operation, capture=True))
        custody = checked(custody, "custodian.cafi.test")
        soap = json.loads(self.compose(
            "run", "--rm", "-T", "--no-deps", "--entrypoint", "python",
            "administrator-worker", "-c", SOAP_PROBE, self.operation, capture=True))
        soap = checked(soap, "administrator.cafi.test")
        entry = administrator_worker[0]
        assert (entry["signatureProfile"], entry["policyVersion"], entry["keyId"]) == (
            "ECDSA", 1, "PLATFORM-0")
        assert (entry["protocol"], entry["group"].upper(), entry["ciphersuite"],
                entry["peerDnsSan"], entry["verifyCode"]) == (
                    *TLS, "administrator.cafi.test", 0)
        platform = [row for row in self.wire("platform") if "signatureProfile" in row]
        custodian = [row for row in self.wire("custodian") if "signatureProfile" in row]
        administrator = [json.loads(line) for line in self.compose(
            "logs", "--no-log-prefix", "administrator", capture=True).splitlines()]
        administrator = [row for row in administrator if row.get("operationId") == self.operation]
        assert platform and custodian and administrator
        assert all(row["group"].upper() == "X25519"
                   and row["signatureProfile"] == "ECDSA"
                   and row["policyVersion"] == 1 for row in platform + custodian + administrator)
        assert all(row["sender"] == "GESTORA-ALFA" for row in platform)
        assert all(row["sender"] == "PLATFORM" for row in custodian + administrator)
        assert all((row["protocol"], row["group"].upper(), row["ciphersuite"],
                    row["peerDnsSan"], row["verifyCode"]) == (
                        *TLS, "platform.cafi.test", 0) for row in administrator)
        keys = {"managerToPlatform": platform[-1]["keyId"],
                "platformToCustodian": custodian[-1]["keyId"],
                "platformToAdministrator": administrator[-1]["keyId"]}
        assert keys == {"managerToPlatform": "PLATFORM-0",
                        "platformToCustodian": "CUSTODIANTE-GAMA-0",
                        "platformToAdministrator": "ADMINISTRADOR-DELTA-0"}
        print(json.dumps({"scenario": "tls-links", "operationId": self.operation,
                          "managerToPlatform": manager, "platformToCustodian": custody,
                          "platformToAdministrator": soap, "serverLogsChecked":
                          {"platform": len(platform), "custodian": len(custodian),
                           "administrator": len(administrator)}, "responseKeyIds": keys,
                          "signatureProfile": "ECDSA", "policyVersion": 1}), flush=True)
    return original_evidence(self, states, **values)


if __name__ == "__main__":
    integrated.Flow.once = once
    integrated.Flow.evidence = evidence
    original_init = integrated.Flow.__init__

    def init(self, name):
        original_init(self, name)
        self.link_observations = {}

    integrated.Flow.__init__ = init
    integrated.main()
