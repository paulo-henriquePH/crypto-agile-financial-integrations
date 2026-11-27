"""External SOAP client over the approved h11/OpenSSL path; no DB credentials."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import ctypes as c
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import socket
import sys
from threading import Barrier, Lock
from time import monotonic, sleep
from uuid import uuid4

import h11

from c1.runtime import ECDSA, ROOT, body, connect, http, private_sign, tls
from c1.security import Route, fields
from c1.transport import receive_response_wire, request_headers
from c1.soap import C, S, envelope
from services.platform.messages import CREDENTIAL, SECRET, boundary

REGISTER, QUERY = 'REGISTER_OPERATION', 'QUERY_ADMIN_RECORD'
PEER = 'administrator.cafi.test'
TLS = ('TLSv1.3', 'X25519', 'TLS_AES_256_GCM_SHA384', 0)
SCOPE = 'GESTORA-ALFA', 'FUNDO-ALFA'
BOLETA = json.loads((ROOT / 'fixtures/boletas/valid.json').read_bytes())
SETTLED = dict(managerId=SCOPE[0], boleta={**BOLETA, 'quantity': '999999999',
              'unitPrice': '900000000.010000', 'grossAmount': '899999999109999999.99'},
              state='SETTLED', sequence='9007199254740993')
OUT, BACK = boundary(False, 'administrator'), boundary(True, 'administrator')
XSD_LOCK = Lock()


@contextmanager
def connection(peer=PEER):
    end = monotonic() + 15
    while True:
        try:
            sock = socket.create_connection((PEER, 8443), timeout=3)
            break
        except ConnectionRefusedError:
            if monotonic() >= end:
                raise
            sleep(.2)
    with sock, connect(CREDENTIAL, 'platform', sock, server=False, peer_dns=peer) as session:
        o = session.observation
        assert (o['protocol'], o['group'].upper(), o['ciphersuite'], o['verifyCode']) == TLS
        assert o['peerDnsSan'] == PEER
        yield session


def validate_xml(wire):
    # Exercise the actual bytes on each leg against the pinned schema.
    with XSD_LOCK:
        return body.parse_xml(wire, XSD).content


def prepare(session, op, payload=None, *, scoped=True, prefix=None, **kwargs):
    kind = QUERY if payload is None else REGISTER
    route = Route.expected(kind, op)
    template = envelope(OUT.policy, kind, op, payload or {}, **kwargs)
    if prefix:
        template = template.replace(b'xmlns:c=', b'xmlns:' + prefix + b'=')
        template = template.replace(b'<c:', b'<' + prefix + b':').replace(b'</c:', b'</' + prefix + b':')
    wire, ctx = OUT.sign(template, route, SECRET, session, lookup=lambda _: SCOPE if scoped else None)
    validate_xml(wire)
    return route, wire, ctx


def attempt(item, *, gate=None, route=None, wrong_correlation=False, reply_sizes=None):
    actual, wire, ctx = item
    with connection() as session:
        if gate:
            gate.wait(timeout=10)
        session.link.send(request_headers(route or actual, session, wire), wire)
        if wrong_correlation:
            try:
                receive_response_wire(session, BACK, actual, replace(ctx, message=str(uuid4())))
            except ValueError as exc:
                assert str(exc) == 'response correlation'
                return
            raise AssertionError('client accepted a genuine response to the wrong request ID')
        status, signed, reply = receive_response_wire(session, BACK, actual, ctx)
    if reply_sizes is not None:
        reply_sizes.append(len(reply))
    assert body.c14n(signed) == body.c14n(validate_xml(reply))
    p, payload = fields(signed.find(C + 'Protected')), fields(signed.find(C + 'Payload'))
    assert (p['requestMessageId'], p['operationId'], p['instructionVersion'], p['senderId'], p['recipientId'],
            p['environment']) == (ctx.message, ctx.operation, 1, 'ADMINISTRADOR-DELTA', 'PLATFORM', 'LAB')
    assert p['messageId'] != ctx.message
    path = signed.getparent().getparent()
    if status == 200:
        assert path.tag == S + 'Body' and p['messageType'] == ctx.action + '_RESULT'
    else:
        assert path.tag == S + 'Detail' and path.getparent().tag == S + 'Fault' and p['messageType'] == 'ERROR'
        assert payload['correlationId'] == ctx.message
    return status, p, payload


def expect_snapshot(result, payload):
    assert result[0] == 200 and result[2] == payload, result
    assert type(result[2]['sequence']) is str  # internal SOAP projection, not a JSON wire type


def expect_fault(result, code, message=None, status=400):
    assert result[0] == status
    assert result[2] == dict(code=code, message=message or code, retryable=status == 500, details=[],
                             correlationId=result[1]['requestMessageId']), result


def prepare_new(*args, **kwargs):
    with connection() as session:
        return prepare(session, *args, **kwargs)


def exercise(op):
    absent = prepare_new(op, scoped=False)
    expect_fault(attempt(absent), 'NOT_FOUND')

    first, reissue = prepare_new(op, SETTLED), prepare_new(op, SETTLED, prefix=b'cafi')
    gate = Barrier(3)
    with ThreadPoolExecutor(3) as pool:
        results = list(pool.map(lambda item: attempt(item, gate=gate), (first, first, reissue)))
    for result in results:
        expect_snapshot(result, SETTLED)
    assert len({r[1]['messageId'] for r in results}) == 3
    assert first[2].message != reissue[2].message

    expect_fault(attempt(absent), 'NOT_FOUND')  # exact replay can replay its observation
    expect_snapshot(attempt(prepare_new(op)), SETTLED)  # new query sees the committed snapshot
    attempt(first, wrong_correlation=True)  # genuine response must fail with a different context

    route, wire, ctx = first
    expect_fault(attempt((route, wire + b' ', ctx)), 'IDEMPOTENCY_CONFLICT', 'MESSAGE_ID_REUSED')
    changed = {**SETTLED, 'sequence': '9007199254740994'}
    expect_fault(attempt(prepare_new(op, changed)), 'IDEMPOTENCY_CONFLICT', 'BUSINESS_DIGEST_MISMATCH')

    mid = str(uuid4())
    collision = [prepare_new(str(uuid4()), scoped=False, message_id=mid) for _ in range(2)]
    gate = Barrier(2)
    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(lambda item: attempt(item, gate=gate), collision))
    winner, loser = sorted(responses, key=lambda r: r[2]['code'] != 'NOT_FOUND')
    expect_fault(winner, 'NOT_FOUND')
    expect_fault(loser, 'IDEMPOTENCY_CONFLICT', 'MESSAGE_ID_REUSED')

    for extras in (
        dict(state='REJECTED', reason='OPERATIONAL_DENIAL', rejectionOrigin='CUSTODIAN'),
        dict(state='REJECTED', reason='GROSS_AMOUNT_MISMATCH', rejectionOrigin='LOCAL',
             boleta={**BOLETA, 'grossAmount': '1.00'}),
        dict(state='SETTLEMENT_FAILED', reason='INSUFFICIENT_CASH'),
    ):
        terminal = dict(managerId=SCOPE[0], boleta=BOLETA, sequence='4') | extras
        other = str(uuid4())
        expect_snapshot(attempt(prepare_new(other, terminal)), terminal)
        expect_snapshot(attempt(prepare_new(other)), terminal)

    invalid = {**SETTLED, 'boleta': {**BOLETA, 'grossAmount': '1.00'}}
    expect_fault(attempt(prepare_new(str(uuid4()), invalid)), 'INVALID_BUSINESS', 'GROSS_AMOUNT_MISMATCH')
    print(json.dumps(dict(messageId=ctx.message, wireDigest=sha256(wire).hexdigest(),
                          responses=len(results), correlationId=results[0][1]['requestMessageId'])))


def bare(route, wire, status, extra=()):
    with connection() as session:
        req = request_headers(route, session, wire)
        head = h11.Request(method=req.method, target=req.target, headers=[*req.headers, *extra])
        session.link.send(head, wire)
        reply, data = session.link.receive(h11.Response)
        assert (reply.status_code, data) == (status, b''), (reply.status_code, wire[:160])


def raw_sign(template, key=None):
    parsed = body.parse_xml(template, XSD)
    kid = OUT.policy.signing_key_id
    sig = private_sign(OUT.crypto, SECRET, OUT.keys[kid].spki, parsed.canonical)
    node = parsed.content.getparent().find(C + 'Signatures/' + C + 'Signature')
    node.text = base64.b64encode(sig).decode()
    assert parsed.signatures[0][:2] == (ECDSA, key or kid)
    return body.etree.tostring(parsed.content.getroottree(), encoding='utf-8')


def channel_rejections(wire, route):
    def reject(block):
        try:
            block()
        except http.TLSFailure:
            return
        raise AssertionError('unexpected accepted TLS exchange')

    def wrong_name():
        with connection('untrusted-name.cafi.test'):
            raise AssertionError('wrong SAN accepted')

    def try_exchange(certificate, group):
        api = tls.OpenSSL()
        with socket.create_connection((PEER, 8443), timeout=3) as sock, \
                api.context(CREDENTIAL, certificate, server=False, group=group) as (ctx, _), \
                http.channel(api, ctx, sock, server=False, group=group, peer=PEER,
                             limit=body.MAX_BYTES) as (link, _):
            link.send(h11.Request(method='POST', target=route.path, headers=[
                ('Host', PEER), ('Content-Type', route.media), ('Content-Length', str(len(wire)))]), wire)
            link.receive(h11.Response)

    reject(wrong_name)
    reject(lambda: try_exchange(None, tls.X25519))
    reject(lambda: try_exchange('platform', tls.HYBRID))


def reject_oversized(route):
    sent = False
    try:
        with connection() as session:
            head = h11.Request(method='POST', target=route.path, headers=[
                ('Host', PEER), ('Content-Type', route.media), ('Content-Length', str(body.MAX_BYTES + 1))])
            data, count = session.link.http.send(head), c.c_size_t()
            session.link.io('write', session.link.api.SSL_write_ex, data, len(data), c.byref(count))
            assert count.value == len(data)
            sent = True
            session.link.receive(h11.Response)
    except http.TLSFailure as exc:
        assert sent and exc.detail['stage'] == 'read'
        return
    raise AssertionError('oversized request not refused at Content-Length')


def negatives(op):
    route, wire, ctx = prepare_new(op, SETTLED)
    vector_dir = ROOT / 'contracts/vectors/xml'
    cases = json.loads((vector_dir / 'manifest.json').read_bytes())['cases']
    vectors = [item for item in cases if 'reject' in item]
    for item in vectors:
        bare(route, (vector_dir / item['input']).read_bytes(), 400)
    original = validate_xml(wire)
    wrapped = (b'<c:Shadow>' + body.etree.tostring(original) + b'</c:Shadow>')
    malformed = (
        wire.replace(b'<s:Body>', b'<s:Header>' + wrapped + b'</s:Header><s:Body>'),
        wire.replace(b'<s:Body>', b'<s:Body><c:Extra/>'),
        wire.replace(b'urn:cafi:v1', b'urn:cafi:v2'),
        wire.replace(b'<c:SignedContent>', b'<c:SignedContent><c:Payload/>', 1),
        wire.replace(b'<c:Sequence>', b'<c:Sequence>0', 1),
        b'<a>' * 33 + b'</a>' * 33,
        b'<?cafi test?>' + wire,
    )
    for data in malformed:
        bare(route, data, 400)
    for data in (
        wire.replace(b'6.500000', b'6.600000', 1),
        wire.replace(b'<c:SignedContent>', b'<c:SignedContent>\n', 1),
        raw_sign(envelope(replace(OUT.policy, sender='GESTORA-ALFA'), REGISTER, op, SETTLED)),
        raw_sign(envelope(replace(OUT.policy, recipient='OTHER'), REGISTER, op, SETTLED)),
        raw_sign(envelope(replace(OUT.policy, environment='OTHER'), REGISTER, op, SETTLED)),
        raw_sign(envelope(replace(OUT.policy, signing_key_id='UNAUTHORIZED'), REGISTER, op, SETTLED),
                 'UNAUTHORIZED'),
    ):
        bare(route, data, 401)
    wrong_scope = {**SETTLED, 'boleta': {**SETTLED['boleta'], 'portfolioId': 'FUNDO-OUTRO'}}
    bad_recipient = {**SETTLED, 'boleta': {**SETTLED['boleta'], 'administratorId': 'OTHER'}}
    for payload in (wrong_scope, bad_recipient):
        data = raw_sign(envelope(OUT.policy, REGISTER, op, payload, message_id=ctx.message))
        expect_fault(attempt((route, data, ctx)), 'FORBIDDEN')
    expect_fault(attempt((route, wire, ctx), route=Route.expected(QUERY, op)), 'INVALID_SCHEMA')
    bare(route, wire, 400, extra=[('SOAPAction', '"urn:cafi:administrator:v1:GetOperation"')])
    channel_rejections(wire, route)
    reject_oversized(route)
    print(json.dumps(dict(xml=len(vectors) + len(malformed), authentication=6, scope=2, action=2, tls=3,
                          body_limit=1)))


def expiry(op):
    with connection() as session:
        issued = datetime.now(UTC)
        prepared = prepare(session, op, SETTLED, issued=issued, lifetime=2)
    expect_snapshot(attempt(prepared), SETTLED)
    sleep(max(0, (issued + timedelta(seconds=7) - datetime.now(UTC)).total_seconds()) + .1)
    bare(prepared[0], prepared[1], 401)


def decimal_digits(length):
    return ('98765432101234567890' * ((length + 19) // 20))[:length]


def sequence_boundary(large_op):
    assert sys.get_int_max_str_digits() == 4300  # default protection still in force
    witnesses = []
    for length in (4300, 4301, 150001):  # last also exceeds PostgreSQL numeric's whole-digit limit
        op = large_op if length == 150001 else str(uuid4())
        payload = {**SETTLED, 'sequence': decimal_digits(length)}
        first = prepare_new(op, payload)
        expect_snapshot(attempt(first), payload)
        expect_snapshot(attempt(prepare_new(op)), payload)
        witnesses.append(dict(operationId=op, digits=length, requestBytes=len(first[1]),
                              sequenceSha256=sha256(payload['sequence'].encode()).hexdigest()))

        if length == 4301:
            r, w, ctx = first
            expect_snapshot(attempt(first), payload)
            # Same XML value/C14N, different transport bytes. A new message ID
            # reuses the logical result; the old one cannot be repurposed.
            reissued = prepare_new(op, payload)
            reference = lambda data: data.replace(b'<c:Sequence>9', b'<c:Sequence>&#x39;', 1)
            assert body.c14n(validate_xml(reissued[1])) == body.c14n(validate_xml(reference(reissued[1])))
            expect_snapshot(attempt((r, reference(reissued[1]), reissued[2])), payload)
            expect_fault(attempt((r, reference(w), ctx)), 'IDEMPOTENCY_CONFLICT', 'MESSAGE_ID_REUSED')
            changed = payload['sequence'][:-1] + '0'
            assert changed != payload['sequence']
            expect_fault(attempt(prepare_new(op, {**payload, 'sequence': changed})),
                         'IDEMPOTENCY_CONFLICT', 'BUSINESS_DIGEST_MISMATCH')
            original = payload['sequence'].encode()
            bare(r, w.replace(original, changed.encode(), 1), 401)
            invalid = (b'0', b'0' + original, b'+' + original, b'-' + original,
                       original + b'.0', original + b' ', b'\xd9\xa9' + original[1:])
            for value in invalid:
                bare(r, w.replace(original, value, 1), 400)
            # PolicyVersion has wider XSD syntax, but C1 still admits only 1.
            template = envelope(OUT.policy, REGISTER, op, payload)
            bigger_policy = template.replace(b'<c:PolicyVersion>1<', b'<c:PolicyVersion>' + original + b'<', 1)
            bare(r, raw_sign(bigger_policy), 400)
            bare(r, w.replace(b'<c:InstructionVersion>1<', b'<c:InstructionVersion>2<', 1), 400)
            bare(r, w.replace(b'<c:Quantity>999999999<', b'<c:Quantity>9999999999<', 1), 400)
            bare(r, w.replace(b'<c:UnitPrice>900000000.010000<',
                              b'<c:UnitPrice>900000000.0100000<', 1), 400)
    print(json.dumps(dict(witnesses=witnesses, bareRejections=12, signedConflicts=2,
                          intMaxStrDigits=sys.get_int_max_str_digits())))


def envelope_budget(exact_op):
    def prepare_exact(op, payload):
        route, wire, ctx = prepare_new(op, payload)
        assert len(wire) <= body.MAX_BYTES
        wire += b' ' * (body.MAX_BYTES - len(wire))
        assert len(wire) == body.MAX_BYTES and validate_xml(wire) is not None
        return route, wire, ctx

    def bound(op, payload):
        dummy = '00000000-0000-0000-0000-000000000001'
        # Compute the full emitted XML plus Base64 expansion, without using
        # the admission predicate. Both WSDL response kinds are checked.
        return max(len(envelope(BACK.policy, action + '_RESULT', op, payload, correlation=dummy,
                                issued=datetime(2000, 1, 1, tzinfo=UTC))) + (96 - len('AA=='))
                   for action in (REGISTER, QUERY))

    def case(label, op, template, digits, accepted):
        payload = {**template, 'sequence': decimal_digits(digits)}
        maximum = bound(op, payload)
        assert (maximum <= body.MAX_BYTES) == accepted
        signed = prepare_exact(op, payload)
        sizes, receipt_ids = [], [signed[2].message]
        create = attempt(signed, reply_sizes=sizes)
        if accepted:
            expect_snapshot(create, payload)
            replay = attempt(signed, reply_sizes=sizes)
            expect_snapshot(replay, payload)
        else:
            expect_fault(create, 'INVALID_BUSINESS', 'SNAPSHOT_RESPONSE_TOO_LARGE')
            if label == 'reported':
                replay = attempt(signed, reply_sizes=sizes)
                expect_fault(replay, 'INVALID_BUSINESS', 'SNAPSHOT_RESPONSE_TOO_LARGE')
                reissue = prepare_exact(op, payload)
                receipt_ids.append(reissue[2].message)
                expect_fault(attempt(reissue, reply_sizes=sizes), 'INVALID_BUSINESS', 'SNAPSHOT_RESPONSE_TOO_LARGE')
        query = prepare_new(op, scoped=accepted)
        receipt_ids.append(query[2].message)
        current = attempt(query, reply_sizes=sizes)
        if accepted:
            expect_snapshot(current, payload)
            assert all(n <= maximum for n in sizes)
        else:
            expect_fault(current, 'NOT_FOUND')
        assert all(n <= body.MAX_BYTES for n in sizes)
        return dict(case=label, operationId=op, digits=digits, requestBytes=len(signed[1]),
                    maxSuccessBytes=maximum, responseBytes=sizes, receipts=receipt_ids,
                    accepted=accepted)

    rejected_with_reason = {**SETTLED, 'state': 'REJECTED', 'reason': '<&> ação \U0001d11e\r\nlinha 2',
                            'rejectionOrigin': 'CUSTODIAN'}
    edge_op = str(uuid4())
    edge = 1 + body.MAX_BYTES - bound(edge_op, {**rejected_with_reason, 'sequence': '9'})
    observations = [
        case('reported', exact_op, SETTLED, 260162, False),
        case('control', str(uuid4()), SETTLED, 259900, True),
        case('response-limit', edge_op, rejected_with_reason, edge, True),
        case('response-limit-plus-one', str(uuid4()), rejected_with_reason, edge + 1, False),
    ]
    assert observations[2]['maxSuccessBytes'] == body.MAX_BYTES
    assert observations[3]['maxSuccessBytes'] == body.MAX_BYTES + 1
    print(json.dumps(dict(cases=observations)))


if __name__ == '__main__':
    XSD = body.soap_schema(ROOT / 'contracts')
    phase, op, *args = sys.argv[1:]
    if phase == 'exercise':
        exercise(op)
    elif phase == 'negatives':
        negatives(op)
    elif phase == 'expiry':
        expiry(op)
    elif phase == 'sequence':
        sequence_boundary(op)
    elif phase == 'envelope-budget':
        envelope_budget(op)
    elif phase == 'restart':
        expect_snapshot(attempt(prepare_new(op)), SETTLED)
        expect_snapshot(attempt(prepare_new(args[0])), {**SETTLED, 'sequence': decimal_digits(150001)})
    elif phase == 'rollback':
        expect_fault(attempt(prepare_new(op, SETTLED)), 'UNAVAILABLE', status=500)
    elif phase == 'revoked':
        expect_fault(attempt(prepare_new(op, SETTLED)), 'FORBIDDEN')
        expect_fault(attempt(prepare_new(op)), 'FORBIDDEN')
        expect_fault(attempt(prepare_new(str(uuid4()), scoped=False)), 'FORBIDDEN')
    else:
        raise ValueError('unexpected phase')
