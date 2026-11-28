"""Run each candidate listener in a child process on a fresh loopback TCP port."""
import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from importlib.metadata import version
import json
from multiprocessing import get_context
import os
from pathlib import Path
import platform
import socket
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.extend(str(ROOT / p) for p in ('spikes/tls', 'spikes/s2-02', 'tests/contracts'))
from certificates import issue_ca, issue_leaf
from proof import OpenSSL, HYBRID, X25519, SET_MIN_PROTO_VERSION, SET_MAX_PROTO_VERSION, checked, require
import envelopes as e
from signed_crypto import OpenSSL as EVP
from transport import Endpoint, TLSFailure, channel

CORPUS = ROOT / 'contracts/vectors/signed/corpus'
PEERS = {'manager': 'GESTORA-ALFA', 'platform': 'PLATFORM',
         'custodian': 'CUSTODIANTE-GAMA', 'administrator': 'ADMINISTRADOR-DELTA'}
JSON = b'application/json'
SOAP = b'application/soap+xml'


@dataclass(frozen=True)
class Policy:
    client: str
    server: str
    endpoint: Endpoint
    operation: str

    def wire(self, role):
        suffix = 'xml' if self.server == 'administrator' else 'json'
        return (CORPUS / f'{self.server}-ecdsa-{role}.{suffix}').read_bytes()


LINKS = [
    Policy('manager', 'platform', Endpoint(b'/v1/operations', JSON, JSON, 201), 'CREATE_OPERATION'),
    Policy('platform', 'custodian', Endpoint(b'/v1/instructions', JSON, JSON, 202), 'SUBMIT_INSTRUCTION'),
    Policy('platform', 'administrator', Endpoint(b'/soap', SOAP + b'; action="urn:cafi:administrator:v1:RegisterOperation"',
                                                SOAP, 200), 'REGISTER_OPERATION'),
]


def dns(role):
    return role + '.cafi.test'


@contextmanager
def pki():
    with TemporaryDirectory(dir='/tmp') as tmp:
        directory = Path(tmp)
        for ca in ('lab-ca', 'other-ca'):
            issue_ca(directory, ca)
        for role in PEERS:
            for rogue in (False, True):
                # Platform acts as both client and server on distinct links.
                purpose = {'platform': 'clientAuth,server', 'manager': 'client'}.get(role, 'server')
                issue_leaf(directory, ('rogue-' if rogue else '') + role,
                           'other-ca' if rogue else 'lab-ca', purpose, dns(role), role)
        for ca in ('lab-ca', 'other-ca'):
            (directory / f'{ca}.key').unlink()
        require(all(p.stat().st_mode & 0o777 == 0o600 for p in directory.glob('*.key')), 'key mode')
        yield directory


class IdentityMismatch(ValueError):
    pass


class Receiver:
    def __init__(self, policy, peer_san, server):
        peer, local = (policy.client, policy.server) if server else (policy.server, policy.client)
        require(peer_san == dns(peer), 'verified peer not in local policy')
        sender = PEERS[peer]
        keys = json.loads((CORPUS / 'trust.json').read_bytes())['keys']
        self.trust = {(k['algorithm'], k['keyId']): base64.b64decode(k['public'], validate=True)
                      for k in keys if k['senderId'] == sender}
        self.crypto = EVP()
        is_xml = policy.server == 'administrator'
        schema = e.soap_schema(ROOT / 'contracts') if is_xml else None
        expected_type = policy.operation + ('' if server else '_RESULT')

        def parse(body):
            parsed = e.parse_xml(body, schema) if is_xml else e.parse_json(body)
            if is_xml:
                p = parsed.content.find(e.C + 'Protected')
                fields = tuple(e.text(p.find(e.C + k)) for k in ('SenderId', 'RecipientId', 'MessageType'))
            else:
                p = parsed.content['protected']
                fields = (p['senderId'], p['recipientId'], p['messageType'])
            if fields[0] != sender:
                raise IdentityMismatch('senderId')
            require(fields[1:] == (PEERS[local], expected_type), 'destination or message type')
            return parsed
        self.parse = parse

    def consume(self, body):
        return e.receive(body, self.parse, self.crypto, 'ECDSA', self.trust, lambda content: content)


def side(directory, policy, case, group, sock, server):
    api = OpenSSL()
    local, peer = (policy.server, policy.client) if server else (policy.client, policy.server)
    certificate = local
    if case == ('untrusted_server' if server else 'untrusted_client'):
        certificate = 'rogue-' + local
    if not server:
        if case == 'missing_client':
            certificate = None
        elif case == 'other_participant':
            certificate = 'manager' if local == 'platform' else 'platform'
        elif case == 'incompatible_groups':
            group = HYBRID if group == X25519 else X25519
    peer_name = dns(peer) if server or case != 'wrong_server_name' else dns('unrelated')
    result = {'consumed': False}
    with api.context(directory, certificate, server=server, group=group) as (ctx, controls):
        # Deliberately incompatible test clients; never retry with another policy.
        if not server and case == 'tls12_only':
            for command in (SET_MIN_PROTO_VERSION, SET_MAX_PROTO_VERSION):
                checked(api.SSL_CTX_ctrl(ctx, command, 0x0303, None), 'test client TLS 1.2 only')
        if not server and case == 'other_suite':
            checked(api.SSL_CTX_set_ciphersuites(ctx, b'TLS_AES_128_GCM_SHA256'), 'test client suite')
        try:
            with channel(api, ctx, sock, server=server, group=group, peer=peer_name, limit=e.MAX_BYTES) as (link, obs):
                receiver = Receiver(policy, obs['peerDnsSan'], server)
                def consume(body):
                    receiver.consume(body)
                    require(body == policy.wire('request' if server else 'response'), 'wire bytes changed')
                    result['consumed'] = True
                if server:
                    def handle(body):
                        consume(body)
                        return policy.wire('response')
                    policy.endpoint.serve(link, handle)
                else:
                    role = 'response' if case == 'wrong_sender' else 'request'
                    consume(policy.endpoint.post(link, peer_name, policy.wire(role)))
                result.update(tls=obs, context=controls)
        except TLSFailure as exc:
            result['failure'] = exc.detail
        except IdentityMismatch:
            result['policyFailure'] = 'senderId'
    return result


def listen(pipe, directory, policy, case, group):
    with pipe, socket.socket() as listener:
        listener.settimeout(5)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        pipe.send(listener.getsockname())
        conn, _ = listener.accept()
        with conn:
            pipe.send(side(directory, policy, case, group, conn, True))


def exchange(directory, policy, case, group):
    ctx = get_context('spawn')
    inbox, outbox = ctx.Pipe(duplex=False)
    child = ctx.Process(target=listen, args=(outbox, directory, policy, case, group))
    child.start()
    outbox.close()
    try:
        require(inbox.poll(10), 'listener startup timeout')
        with socket.create_connection(inbox.recv(), timeout=3) as conn:
            client = side(directory, policy, case, group, conn, False)
        require(inbox.poll(12), 'listener result timeout')
        server = inbox.recv()
        child.join(5)
        require(child.exitcode == 0, 'listener exit')
        return client, server
    finally:
        inbox.close()
        if child.is_alive():
            child.kill()
        child.join()
        child.close()


NEGATIVES = {
    'wrong_server_name': ('client', 'certificate verify failed', 62),
    'untrusted_server': ('client', 'certificate verify failed', 20),
    'untrusted_client': ('server', 'certificate verify failed', 20),
    'missing_client': ('server', 'peer did not return a certificate', 0),
    'other_participant': ('server', 'certificate verify failed', 62),
    'incompatible_groups': ('server', 'no suitable key share', 0),
    'tls12_only': ('server', 'unsupported protocol', 0),
    'other_suite': ('server', 'no shared cipher', 0),
}


def gate():
    versions = {k: version(k) for k in ('h11', 'rfc8785', 'lxml')}
    require(versions == {'h11': '0.16.0', 'rfc8785': '0.1.4', 'lxml': '6.1.3'}, 'package versions')
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'platform')
    results = []
    with pki() as directory:
        for policy in LINKS:
            for group in (X25519, HYBRID):
                client, server = exchange(directory, policy, 'positive', group)
                require(client['consumed'] and server['consumed'], 'signed exchange failed')
                row = {'clientParticipant': policy.client, 'serverParticipant': policy.server,
                       'requiredGroup': group.decode(), 'client': client, 'server': server, 'rejections': {}}
                for case in [*NEGATIVES, 'wrong_sender']:
                    client, server = exchange(directory, policy, case, group)
                    require(not client['consumed'] and not server['consumed'], case + ': consumed')
                    if case == 'wrong_sender':
                        require(server.get('policyFailure') == 'senderId' and 'failure' in client, case)
                        row['rejections'][case] = {'at': 'server', 'reason': 'senderId'}
                    else:
                        at, reason, code = NEGATIVES[case]
                        failure = (server if at == 'server' else client)['failure']
                        require((failure['stage'], failure['sslError'], failure['reason'], failure['verifyCode'])
                                == ('handshake', 1, reason, code) and 'failure' in server and 'failure' in client,
                                f'{case}: {client}, {server}')
                        row['rejections'][case] = {'at': at, **failure}
                results.append(row)
    sources = [Path(__file__), Path(__file__).with_name('transport.py'), ROOT / 'spikes/tls/proof.py',
               ROOT / 'spikes/tls/certificates.py', ROOT / 'spikes/s2-02/envelopes.py', ROOT / 'tests/contracts/signed_crypto.py']
    api = OpenSSL()
    return {'result': 'passed', 'system': platform.system(), 'machine': platform.machine(),
            'checkoutRevision': os.environ['CAFI_CODE_REVISION'], 'imageId': os.environ['CAFI_IMAGE_ID'],
            'runtime': api.runtime, 'openssl': api.version, 'packages': versions,
            'sourcesSHA256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
            'exchanges': results}


if __name__ == '__main__':
    print(json.dumps(gate(), indent=2))
