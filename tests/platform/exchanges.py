"""External manager tests. This container has neither SQL credentials nor a platform key."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import sys
from threading import Barrier
from uuid import uuid4

import h11
from c1.runtime import ROOT, body, connect, private_sign
from c1.security import JSON, Route
from c1.transport import request_headers, receive_response
from services.platform.messages import CREDENTIAL, SECRET, boundary, envelope

OUT, BACK = boundary(False), boundary(True)
B = json.loads((ROOT / 'fixtures/boletas/valid.json').read_bytes())
SCOPE = ('GESTORA-ALFA', 'FUNDO-ALFA')


def exchange(b=None, op=None, *, raw=None, override=None, gate=None, invalid=None, bare=None, path_op=None):
    action = 'QUERY_OPERATION' if op else 'CREATE_OPERATION'
    route = Route('POST', f'/v1/operations/{op}/status-queries' if op else '/v1/operations', JSON)
    with socket.create_connection(('platform.cafi.test', 8443), timeout=5) as sock, connect(
            CREDENTIAL, 'manager', sock, server=False, peer_dns='platform.cafi.test') as s:
        if raw is None:
            template = envelope(OUT.policy, action, {} if op else b, op, **(override or {}))
            if gate:
                gate.wait(timeout=8)  # first client-side parse is concurrent too
            raw, ctx = OUT.sign(template, route, SECRET, s, lookup=lambda _: SCOPE)
        else:
            # Reconstruct the local attempt from the originally sent bytes.
            _, ctx = OUT.sign(raw, route, SECRET, s, lookup=lambda _: SCOPE)
        if invalid:
            obj = json.loads(raw)
            invalid(obj)
            parsed = body.parse_json(json.dumps(obj).encode())
            _, kid, _ = parsed.signatures[0]
            obj['signatures'][0]['value'] = base64.b64encode(private_sign(
                OUT.crypto, SECRET, OUT.keys[kid].spki, parsed.canonical)).decode()
            raw = json.dumps(obj).encode()
        if gate:
            gate.wait(timeout=8)
        wire_route = Route('POST', f'/v1/operations/{path_op}/status-queries', JSON) if path_op else route
        s.link.send(request_headers(wire_route, s, raw), raw)
        if bare:
            head, data = s.link.receive(h11.Response)
            assert (head.status_code, data) == (bare, b'')
            return
        status, response = receive_response(s, BACK, route, ctx)
        return status, response['protected'].get('operationId'), response['payload'], raw


def denial(result, status, code):
    assert result[0] == status and result[2]['code'] == code
    assert set(result[2]) == {'code', 'message', 'retryable', 'details', 'correlationId'}
    assert result[2]['message'] == code and result[2]['details'] == []


def first():
    barrier = Barrier(2)
    with ThreadPoolExecutor(2) as pool:
        a, b = pool.map(lambda _: exchange(B, gate=barrier), range(2))
    assert sorted((a[0], b[0])) == [200, 201] and a[1:3] == b[1:3]
    op = a[1]
    assert a[2] == dict(managerId=SCOPE[0], boleta=B, state='VALIDATED', sequence=2)
    assert exchange(raw=a[3])[:3] == (200, op, a[2])
    denial(exchange(raw=a[3] + b' '), 409, 'IDEMPOTENCY_CONFLICT')
    assert exchange(B)[:3] == (200, op, a[2])
    denial(exchange({**B, 'issuerId': 'OTHER'}), 409, 'IDEMPOTENCY_CONFLICT')
    mid = json.loads(a[3])['protected']['messageId']
    denial(exchange({**B, 'clientOrderId': 'NEW'}, override=dict(messageId=mid)), 409, 'IDEMPOTENCY_CONFLICT')
    # Distinct logical orders, one signed message ID: exactly one transaction commits an order.
    barrier = Barrier(2)
    collision = dict(messageId=str(uuid4()))
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda i: exchange({**B, 'clientOrderId': 'RACE-' + str(i)},
                                                   override=collision, gate=barrier), range(2)))
    winner, loser = sorted(results, key=lambda r: r[0])
    assert winner[0] == 201
    denial(loser, 409, 'IDEMPOTENCY_CONFLICT')
    status, _, payload, _ = exchange(op=op)
    assert status == 200 and [e['state'] for e in payload['events']] == ['REGISTERED', 'VALIDATED']
    assert (payload['deliveryStatus'], payload['reconciliationStatus']) == ('PENDING', 'NOT_READY')
    denial(exchange(op=str(uuid4())), 404, 'NOT_FOUND')
    denial(exchange(op=str(uuid4()), override=dict(messageId=mid)), 409, 'IDEMPOTENCY_CONFLICT')
    for i, (fields, reason) in enumerate([
            ({'grossAmount': '98050.01'}, 'GROSS_AMOUNT_MISMATCH'),
            ({'unitPrice': '99999999999999.999999', 'quantity': '999999999'}, 'GROSS_AMOUNT_OVERFLOW'),
            ({'settlementDate': '2026-11-18'}, 'INVALID_DATES'),
            ({'tradeDate': '2026-11-15'}, 'INVALID_DATES'),
            ({'issuerId': 'UNKNOWN'}, 'ASSET_MISMATCH'),
            ({'counterpartyId': 'UNKNOWN'}, 'UNKNOWN_COUNTERPARTY'),
            ({'administratorId': 'UNKNOWN'}, 'PARTICIPANT_MISMATCH')]):
        rejected = exchange({**B, **fields, 'clientOrderId': f'REJECT-{i}'})
        assert rejected[0] == 201 and rejected[2]['state'] == 'REJECTED'
        assert (rejected[2]['reason'], rejected[2]['rejectionOrigin']) == (reason, 'LOCAL')
        if not i:
            assert exchange(raw=rejected[3])[:3] == (200, *rejected[1:3])
            last = exchange(op=rejected[1])[2]['events'][-1]
            assert (last['reason'], last['rejectionOrigin']) == (reason, 'LOCAL')
    rounded = exchange({**B, 'clientOrderId': 'ROUND', 'quantity': '1',
                        'unitPrice': '0.005000', 'grossAmount': '0.01'})
    assert rounded[0] == 201 and rounded[2]['state'] == 'VALIDATED'
    denial(exchange(B, invalid=lambda obj: obj['payload'].update(quantity='0')), 400, 'INVALID_SCHEMA')
    denial(exchange(B, invalid=lambda obj: obj['payload'].update(portfolioId='OTHER')), 403, 'FORBIDDEN')
    exchange(raw=a[3], invalid=lambda obj: obj['protected'].update(issuedAt='2020-01-01T00:00:00Z',
             expiresAt='2020-01-01T00:02:00Z'), bare=401)
    print('PASS concurrent creation, replay/reissue, both conflicts, seven local rejections, '
          'HALF_UP, signed schema error, forbidden portfolio, expiry, history and signed absence')


if __name__ == '__main__':
    phase, *args = sys.argv[1:]
    if phase == 'first':
        first()
    elif phase == 'advanced':
        result = exchange(op=args[0])
        assert result[0] == 200 and result[2]['state'] == 'SENT' and result[2]['sequence'] == 3
        assert result[2]['events'][-1]['previousState'] == 'VALIDATED'
        assert exchange(B)[2]['state'] == 'VALIDATED'
    elif phase == 'forbidden':
        denial(exchange(op=args[0]), 403, 'FORBIDDEN')
        denial(exchange(B), 403, 'FORBIDDEN')
    elif phase == 'foreign':
        denial(exchange(op=args[0]), 403, 'FORBIDDEN')
    elif phase == 'route':
        other = str(uuid4())
        for protected, path in [(args[0], other), (other, args[0])]:
            result = exchange(op=protected, path_op=path)
            denial(result, 400, 'INVALID_SCHEMA')
            assert result[1] == protected and not result[2]['retryable']
    elif phase == 'rollback':
        result = exchange({**B, 'clientOrderId': 'ROLLBACK'})
        denial(result, 503, 'UNAVAILABLE')
