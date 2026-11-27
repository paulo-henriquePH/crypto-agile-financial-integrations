"""Synthetic contract and access-control tests at the adapter boundary."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import json
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
import h11

from c1 import transport
from c1.policy import direction
from c1.provision import provision
from c1.runtime import ROOT, body, connect, http
from c1.security import (Absent, Boundary, ECDSA, Forbidden, ROUTES, Route, parse,
                         registry, utc)
from spikes.tls.certificates import issue_ca, issue_leaf

CORPUS = ROOT / 'contracts/vectors/signed/corpus'
SCOPE = ('GESTORA-ALFA', 'FUNDO-ALFA')
OP = '11111111-1111-4111-8111-111111111111'
IDS = {'manager': SCOPE[0], 'platform': 'PLATFORM', 'administrator': 'ADMINISTRADOR-DELTA',
       'custodian': 'CUSTODIANTE-GAMA'}
LINKS = {'platform': ('manager', 'CREATE_OPERATION', 'QUERY_OPERATION'),
         'custodian': ('platform', 'SUBMIT_INSTRUCTION', 'QUERY_INSTRUCTION'),
         'administrator': ('platform', 'REGISTER_OPERATION', 'QUERY_ADMIN_RECORD')}
NOW = utc('2026-11-19T12:00:30Z')


def route(action):
    path, media = ROUTES[action]
    return Route('POST', path.format(id=OP), media)


def dns(name):
    return name + '.cafi.test'


def vector(server, role):
    ext = 'xml' if server == 'administrator' else 'json'
    return (CORPUS / f'{server}-ecdsa-{role}.{ext}').read_bytes()


def query_template(wire, action):
    if wire.startswith(b'<'):
        root = body.etree.fromstring(wire)
        node = root.find('.//' + body.C + 'SignedContent')
        node.find(body.C + 'Protected/' + body.C + 'MessageType').text = action
        node.find(body.C + 'Payload').clear()
        return body.etree.tostring(root)
    env = json.loads(wire)
    env['protected'].update(messageType=action, operationId=OP)
    env['payload'] = {}
    return json.dumps(env).encode()


class ColdParsers(unittest.TestCase):
    def test_parallel_json_then_soap_from_cold_process(self):
        subprocess.run([sys.executable, str(ROOT / 'tests/c1/cold_parsers.py')], check=True, timeout=40)


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = TemporaryDirectory(dir='/tmp')
        cls.addClassCleanup(temp.cleanup)
        cls.directory = d = Path(temp.name)
        for ca in ('lab-ca', 'other-ca'):
            issue_ca(d, ca)
        rows = [{**r, 'usage': 'MESSAGE'} for r in json.loads((CORPUS / 'trust.json').read_bytes())['keys']
                if r['algorithm'] == ECDSA]
        cls.static = registry(rows)
        fresh = []
        for role in IDS:
            issue_leaf(d, role, 'lab-ca', 'clientAuth,server', dns(role), role)
            row = next(r for r in rows if r['senderId'] == IDS[role])
            provision(d / role, IDS[role], row['keyId'])
            public, = json.loads((d / role / 'registry.json').read_bytes())
            # Replay the frozen security clock, not the certificate-generation clock.
            fresh.append({**public, 'notBefore': row['notBefore'], 'notAfter': row['notAfter']})
        cls.fresh = registry(fresh)
        issue_leaf(d, 'rogue', 'other-ca', 'client', dns('manager'), 'manager')

    @contextmanager
    def pair(self, server, client_cert=None):
        client = LINKS[server][0]
        with ExitStack() as stack:
            left, right = socket.socketpair()
            stack.enter_context(left)
            stack.enter_context(right)
            listener = connect(self.directory, server, right, server=True, peer_dns=dns(client))
            with ThreadPoolExecutor(1) as pool:
                task = pool.submit(listener.__enter__)
                sender = stack.enter_context(connect(self.directory, client_cert or client, left,
                                                     server=False, peer_dns=dns(server)))
                receiver = task.result()
                stack.push(listener)
            yield sender, receiver

    def boundary(self, server, reverse=False, fresh=False, **changes):
        client, action, query = LINKS[server]
        sender, dest = (server, client) if reverse else (client, server)
        keys = self.fresh if fresh else self.static
        kids = frozenset(k for k, v in keys.items() if v.sender == IDS[sender])
        policy = direction(server, response=reverse, signing_key_id=next(iter(kids)), trusted_key_ids=kids)
        return Boundary(replace(policy, **changes), keys, clock=lambda: NOW)

    def test_frozen_vectors(self):
        for server, (_, action, _) in LINKS.items():
            with self.subTest(server=server), self.pair(server) as (client, service):
                r = route(action)
                _, ctx = self.boundary(server).receive(vector(server, 'request'), r, service, lookup=lambda _: None)
                for role in ('response', 'error'):
                    self.boundary(server, True).receive(vector(server, role), r, client, request=ctx)
                    self.assertLessEqual(len(vector(server, role)), body.MAX_BYTES)
                for role in ('request', 'response', 'error'):
                    parsed, _, _ = parse(vector(server, role), server == 'administrator')
                    ref = CORPUS / f'{server}-ecdsa-{role}.canonical.b64'
                    self.assertEqual(parsed.canonical, base64.b64decode(ref.read_bytes()))

    def test_fresh_http_exchanges(self):
        for server, (sender, command, query) in LINKS.items():
            out, back = self.boundary(server, fresh=True), self.boundary(server, True, True)
            for action, role in [(command, 'response'), (command, 'error'), (query, 'error'), (query, 'response')]:
                with self.subTest(server=server, action=action, role=role), self.pair(server) as (client, service):
                    wire = vector(server, 'request')
                    reply = vector(server, role)
                    if action == query:
                        wire = query_template(wire, query)
                        # Derive a contracted absence from the synthetic conflict.
                        if role == 'response' and server == 'administrator':
                            reply = reply.replace(b'REGISTER_OPERATION_RESULT', b'QUERY_ADMIN_RECORD_RESULT')
                        elif role == 'response':
                            env = json.loads(reply)
                            env['protected'].update(messageType=query + '_RESULT', operationId=OP)
                            cases = json.loads((ROOT / 'contracts/messages/examples.json').read_bytes())['cases']
                            env['payload'] = next(c['message']['payload'] for c in cases if c['name'] == query.lower() + '_result')
                            reply = json.dumps(env).encode()
                        elif server == 'administrator':
                            reply = reply.replace(b'IDEMPOTENCY_CONFLICT', b'NOT_FOUND')
                        else:
                            env = json.loads(reply)
                            env['protected']['operationId'] = OP
                            env['payload']['code'] = 'NOT_FOUND'
                            reply = json.dumps(env).encode()
                    r = route(action)
                    ctx = transport.send_request(client, out, r, wire, self.directory / sender / 'message-private.pem',
                                                 lookup=lambda _: SCOPE)
                    if action == query and role == 'error':
                        with self.assertRaises(Absent) as missing:
                            transport.receive_request(service, out, lookup=lambda _: None)
                        received = missing.exception.request
                    else:
                        actual_route, _, received = transport.receive_request(service, out, lookup=lambda _: SCOPE)
                        self.assertEqual(actual_route, r)
                    status = ({'platform': 201, 'custodian': 202, 'administrator': 200}[server]
                              if role == 'response' else 500 if server == 'administrator'
                              else 404 if action == query else 409)
                    if action == query and role == 'response':
                        status = 200
                    transport.send_response(service, back, r, received, reply, self.directory / server / 'message-private.pem', status)
                    self.assertEqual(transport.receive_response(client, back, r, ctx)[0], status)

    def test_certificates(self):
        for cert, code in [('rogue', 20), ('custodian', 62)]:
            with self.subTest(cert=cert), self.assertRaises(http.TLSFailure) as failure:
                with self.pair('platform', cert):
                    self.fail('unexpected authenticated pair')
            self.assertEqual(failure.exception.detail['verifyCode'], code)

    def test_http_creation_snapshot_is_bound_to_complete_order(self):
        result = vector('platform', 'response')
        out = self.boundary('platform', fresh=True)
        back = self.boundary('platform', reverse=True)
        r = route('CREATE_OPERATION')
        for field, changed in [('clientOrderId', 'OP-000002'), ('counterpartyId', 'INSTITUICAO-ZETA')]:
            with self.subTest(field=field), self.pair('platform') as (client, service):
                template = json.loads(vector('platform', 'request'))
                template['payload'][field] = changed
                ctx = transport.send_request(client, out, r, json.dumps(template).encode(),
                                             self.directory / 'manager/message-private.pem')
                _, signed, received = transport.receive_request(service, out, lookup=lambda _: None)
                # Changing the handler's dictionary cannot change the retained reference.
                signed['payload'][field] = json.loads(result)['payload']['boleta'][field]
                with self.assertRaisesRegex(ValueError, 'creation snapshot differs'):
                    transport.send_response(service, back, r, received, result,
                                            self.directory / 'platform/message-private.pem', 201)
                # Frozen, valid signature; same request ID, manager, portfolio and Location.
                service.link.send(h11.Response(status_code=201, headers=[
                    ('Content-Type', 'application/json'), ('Content-Length', str(len(result))),
                    ('Location', '/v1/operations/' + OP)]), result)
                with self.assertRaisesRegex(ValueError, 'creation snapshot differs'):
                    transport.receive_response(client, back, r, ctx)

    def test_http_signed_error_status(self):
        out, back = self.boundary('platform', fresh=True), self.boundary('platform', True, True)
        secret = self.directory / 'platform/message-private.pem'
        for code, status, rejection in [
                ('FORBIDDEN', 403, None), ('FORBIDDEN', 401, 'authorization status'),
                ('INVALID_SCHEMA', 403, 'authorization status'), ('INVALID_SCHEMA', 400, None),
                ('INVALID_SCHEMA', 422, 'schema status'), ('IDEMPOTENCY_CONFLICT', 503, 'conflict status'),
                ('NOT_FOUND', 503, 'absence status'), ('FORBIDDEN', 404, 'absence status')]:
            with self.subTest(code=code, status=status), self.pair('platform') as (client, service):
                r = route('QUERY_OPERATION')
                template = query_template(vector('platform', 'request'), 'QUERY_OPERATION')
                ctx = transport.send_request(client, out, r, template, self.directory / 'manager/message-private.pem',
                                             lookup=lambda _: SCOPE)
                _, _, received = transport.receive_request(service, out, lookup=lambda _: SCOPE)
                error = json.loads(vector('platform', 'error'))
                error['protected']['operationId'] = OP
                error['payload']['code'] = code
                template = json.dumps(error).encode()
                if rejection is None:
                    transport.send_response(service, back, r, received, template, secret, status)
                    self.assertEqual(transport.receive_response(client, back, r, ctx)[0], status)
                else:
                    with self.assertRaisesRegex(ValueError, rejection):
                        transport.send_response(service, back, r, received, template, secret, status)
                    wire, _ = back.sign(template, r, secret, service, request=received)
                    service.link.send(h11.Response(status_code=status, headers=[
                        ('Content-Type', 'application/json'), ('Content-Length', str(len(wire)))]), wire)
                    with self.assertRaisesRegex(ValueError, rejection):
                        transport.receive_response(client, back, r, ctx)

    def test_rejection_before_replay(self):
        with self.pair('platform') as (client, service):
            r, wire = route('CREATE_OPERATION'), vector('platform', 'request')
            valid = self.boundary('platform')
            _, ctx = valid.receive(wire, r, service, lookup=lambda _: None)
            hits = []
            def replay(b, data=wire, path=r):
                b.receive(data, path, service, lookup=lambda _: SCOPE)
                hits.append(ctx.message)
            replay(valid)
            with self.assertRaisesRegex(Forbidden, 'stored portfolio permission'):
                valid.receive(wire, r, service, lookup=lambda _: ('OTHER', 'OTHER'))
            for changes, reason in [
                    ({'recipient': 'OTHER'}, 'direction'), ({'sender': 'OTHER'}, 'direction'),
                    ({'environment': 'OTHER'}, 'direction'), ({'actions': frozenset()}, 'action permission'),
                    ({'scopes': frozenset()}, 'portfolio permission'), ({'key_ids': frozenset()}, 'unauthorized key')]:
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    replay(self.boundary('platform', **changes))
            valid.clock = lambda: utc('2026-11-19T12:02:06Z')
            with self.assertRaisesRegex(ValueError, 'validity'):
                replay(valid)
            valid.clock = lambda: utc('2026-11-19T11:59:54Z')
            with self.assertRaisesRegex(ValueError, 'validity'):
                replay(valid)
            valid.clock = lambda: NOW
            for data, reason in [
                    (wire.replace(b'98050.00', b'98051.00'), 'invalid signature'),
                    (wire.replace(b'"payload":', b'"payload":{}, "payload":'), 'duplicate property'),
                    (wire.replace(b'"policyVersion": 1', b'"policyVersion": 2'), 'C1 version'),
                    (b' ' * (body.MAX_BYTES + 1), 'size'), (b'[' * 33 + b']' * 33, 'depth')]:
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    replay(valid, data)
            kid = next(iter(valid.policy.key_ids))
            for changes in ({'state': 'REVOKED'}, {'usage': 'TLS'}, {'end': utc('2026-11-19T12:00:29Z')},
                            {'sender': 'OTHER'}, {'spki': service.peer_spki}):
                valid.keys = {kid: replace(self.static[kid], **changes)}
                with self.subTest(key=list(changes)), self.assertRaisesRegex(ValueError, 'inactive key|reuse'):
                    replay(valid)
            self.assertEqual(hits, [ctx.message])
            for changes in ({'message': OP}, {'action': 'QUERY_OPERATION'}, {'operation': OP},
                            {'environment': 'OTHER'}, {'scope': ('OTHER', 'OTHER')}):
                # Creation has no predetermined operation; use an unrelated operation for the mismatch.
                if 'operation' in changes:
                    changes['operation'] = ctx.message
                with self.subTest(ctx=list(changes)), self.assertRaises(ValueError):
                    self.boundary('platform', True).receive(vector('platform', 'response'), r, client,
                                                           request=replace(ctx, **changes))

    def test_query_authorization_and_routes(self):
        for server, (sender, command, query) in LINKS.items():
            with self.subTest(server=server), self.pair(server) as (client, service):
                b = self.boundary(server, fresh=True)
                r = route(query)
                template = query_template(vector(server, 'request'), query)
                wire, _ = b.sign(template, r, self.directory / sender / 'message-private.pem', client, lookup=lambda _: SCOPE)
                _, ctx = b.receive(wire, r, service, lookup=lambda _: SCOPE)
                self.assertEqual(ctx.operation, OP)
                with self.assertRaisesRegex(ValueError, 'portfolio permission'):
                    b.receive(wire, r, service, lookup=lambda _: ('OTHER', SCOPE[1]))
                bad = route(command) if server == 'administrator' else replace(r, path=r.path.replace(OP, ctx.message))
                with self.assertRaisesRegex(ValueError, 'route/action'):
                    b.receive(wire, bad, service, lookup=lambda _: self.fail('unexpected scope lookup'))
                with self.assertRaisesRegex(ValueError, 'invalid signature'):
                    b.receive(wire.replace(ctx.message.encode(), OP.encode()), r, service,
                              lookup=lambda _: self.fail('unexpected scope lookup'))

    def test_xml_parser(self):
        folder = ROOT / 'contracts/vectors/xml'
        with self.pair('administrator') as (_, service):
            b, r = self.boundary('administrator'), route('REGISTER_OPERATION')
            for case in json.loads((folder / 'manifest.json').read_bytes())['cases']:
                if 'reject' in case:
                    with self.subTest(name=case['name']), self.assertRaises(ValueError):
                        b.receive((folder / case['input']).read_bytes(), r, service)
            for wire, reason in [(b'<a>' * 33 + b'</a>' * 33, 'depth'), (b' ' * (body.MAX_BYTES+1), 'size')]:
                with self.assertRaisesRegex(ValueError, reason):
                    b.receive(wire, r, service)

    def test_soap_sequence_projection_preserves_unbounded_integer(self):
        wire = vector('administrator', 'request')
        original = body.parse_xml(wire, body.soap_schema(ROOT / 'contracts')).content
        old = body.text(original.find(body.C + 'Payload/' + body.C + 'Sequence')).encode()
        tag = b'<c:Sequence>' + old + b'</c:Sequence>'
        self.assertIn(tag, wire)
        digits = '1234567890' * 450
        changed = wire.replace(tag, b'<c:Sequence>' + digits.encode() + b'</c:Sequence>', 1)
        _, p, payload = parse(changed, xml=True)
        self.assertEqual(payload['sequence'], digits)
        self.assertEqual((p['instructionVersion'], p['policyVersion']), (1, 1))
        with self.assertRaisesRegex(ValueError, 'C1 version'):
            parse(changed.replace(b'<c:PolicyVersion>1<', b'<c:PolicyVersion>2<', 1), xml=True)
        with self.assertRaisesRegex(ValueError, 'soap schema'):
            parse(changed.replace(b'<c:Sequence>', b'<c:Sequence>0', 1), xml=True)

    def test_http_limit_before_body(self):
        with self.pair('platform') as (client, service):
            # Only a header is sent. Receiver cannot rely on a complete body to apply the limit.
            head = h11.Request(method='POST', target='/v1/operations', headers=[
                ('Host', dns('platform')), ('Content-Type', 'application/json'),
                ('Content-Length', str(body.MAX_BYTES + 1))])
            data = client.link.http.send(head)
            import ctypes as c
            count = c.c_size_t()
            client.link.io('write', client.link.api.SSL_write_ex, data, len(data), c.byref(count))
            self.assertEqual(count.value, len(data))
            with self.assertRaisesRegex(RuntimeError, 'inbound body limit'):
                transport.receive_request(service, self.boundary('platform'))

    def test_emission_keys_and_denial(self):
        with self.pair('platform') as (client, service):
            b = self.boundary('platform', fresh=True)
            wire, r = vector('platform', 'request'), route('CREATE_OPERATION')
            secret = self.directory / 'manager' / 'message-private.pem'
            args = (wire, r, secret, client)
            signed, ctx = b.sign(*args)
            with self.assertRaisesRegex(ValueError, 'wrong signing secret'):
                b.sign(wire, r, self.directory / 'platform' / 'message-private.pem', client)
            kid = b.policy.signing_key_id
            b.keys = {kid: replace(self.fresh[kid], state='VERIFY_ONLY')}
            self.assertEqual(b.receive(signed, r, service, lookup=lambda _: None)[1], ctx)
            with self.assertRaisesRegex(ValueError, 'inactive key'):
                b.sign(*args)
            b = self.boundary('platform', fresh=True, scopes=frozenset())
            with self.assertRaises(Forbidden) as denied:
                b.receive(signed, r, service)
            back = self.boundary('platform', True, True)
            denied_ctx = denied.exception.request
            with self.assertRaisesRegex(ValueError, 'scope'):
                back.sign(vector('platform', 'response'), r, self.directory / 'platform' / 'message-private.pem',
                          service, request=denied_ctx)
            error = json.loads(vector('platform', 'error'))
            error['payload']['code'] = 'FORBIDDEN'
            answer, _ = back.sign(json.dumps(error).encode(), r, self.directory / 'platform' / 'message-private.pem',
                                  service, request=denied_ctx)
            self.assertEqual(back.receive(answer, r, client, request=ctx)[0]['payload']['code'], 'FORBIDDEN')
