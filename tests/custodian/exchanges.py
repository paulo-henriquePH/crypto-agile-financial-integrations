"""External C1 client; no SQL credentials. Each attempt opens a new mTLS session."""
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import json
import sys
from threading import Barrier
import time
from uuid import uuid4

import h11
from c1.runtime import ROOT
from c1.security import Route
from c1.transport import request_headers, receive_response
from services.custodian.client import Client, connection

client = Client()
business = dict(managerId='GESTORA-ALFA', boleta=json.loads((ROOT / 'fixtures/boletas/valid.json').read_bytes()))


def lookup(_):
    return business['managerId'], business['boleta']['portfolioId']


def prepare(op, payload, **kwargs):
    with connection() as s:
        return client.prepare(s, op, payload, lookup, **kwargs)


def attempt(prepared, gate=None):
    with connection() as s:
        if gate:
            gate.wait(timeout=10)
        return client.send(s, *prepared)


def denial(result, status, code, message=None):
    n, response = result
    p = response['payload']
    assert n == status and p == dict(code=code, message=message or code, details=[], retryable=status == 503,
                                    correlationId=response['protected']['requestMessageId'])


def bare(prepared, status):
    route, wire, _ = prepared
    with connection() as s:
        s.link.send(request_headers(route, s, wire), wire)
        head, data = s.link.receive(h11.Response)
        assert (head.status_code, data) == (status, b'')


def snapshot(op):
    status, response = client.exchange(op, None, lookup)
    p = response['payload']
    assert status == 200 and p['state'] == 'RECEIVED' and p['sequence'] == 1
    assert p['boleta'] == business['boleta'] and p['managerId'] == business['managerId']
    event, = p['events']
    assert (event['sequence'], event['operationId'], event['state'], event['previousState'],
            event['origin'], event['instructionVersion']) == (1, op, 'RECEIVED', 'SENT', 'CUSTODIAN', 1)


def receive(op):
    absent = prepare(op, None)
    denial(attempt(absent), 404, 'NOT_FOUND')
    first, reissue = prepare(op, business), prepare(op, dict(reversed(business.items())))
    gate = Barrier(3)
    with ThreadPoolExecutor(3) as pool:
        results = list(pool.map(lambda item: attempt(item, gate), [first, first, reissue]))
    assert all(n == 202 and r['payload'] == dict(sequence=1, state='RECEIVED') for n, r in results)
    assert len({r['protected']['messageId'] for _, r in results}) == 3
    assert first[2].message != reissue[2].message
    denial(attempt(absent), 404, 'NOT_FOUND')
    snapshot(op)
    route, wire, ctx = first
    denial(attempt((route, wire + b' ', ctx)), 409, 'IDEMPOTENCY_CONFLICT', 'MESSAGE_ID_REUSED')
    changed = dict(business, boleta={**business['boleta'], 'clientOrderId': 'DIFFERENT'})
    denial(client.exchange(op, changed, lookup), 409, 'IDEMPOTENCY_CONFLICT', 'BUSINESS_DIGEST_MISMATCH')
    # Distinct operation locks, same message lock. No prior receipt for either query.
    mid = str(uuid4())
    collision = [prepare(str(uuid4()), None, messageId=mid) for _ in range(2)]
    gate = Barrier(2)
    with ThreadPoolExecutor(2) as pool:
        a, b = sorted(pool.map(lambda item: attempt(item, gate), collision), key=lambda x: x[0])
    denial(a, 404, 'NOT_FOUND')
    denial(b, 409, 'IDEMPOTENCY_CONFLICT', 'MESSAGE_ID_REUSED')
    bare((route, wire.replace(b'OP-000001', b'OP-000002'), ctx), 401)
    r, w, c = absent
    with connection() as s:
        other = Route.expected('QUERY_INSTRUCTION', str(uuid4()))
        s.link.send(request_headers(other, s, w), w)
        denial(receive_response(s, client.back, r, c), 400, 'INVALID_SCHEMA')
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=1)
    stamp = lambda t: t.isoformat().replace('+00:00', 'Z')
    short = prepare(op, business, issuedAt=stamp(now), expiresAt=stamp(expires))
    assert attempt(short)[0] == 202
    # Same signed bytes, after expiry including the C1 five-second tolerance.
    time.sleep(max(0, (expires - datetime.now(UTC)).total_seconds()) + 5.1)
    bare(short, 401)
    print('PASS signed absence, concurrent replay/reissue, fresh snapshot, both conflicts, '
          'modified signature input, route correlation, identical expired replay')


if __name__ == '__main__':
    phase, op = sys.argv[1:]
    if phase == 'receive':
        receive(op)
    elif phase == 'snapshot':
        snapshot(op)
    elif phase == 'rollback':
        denial(client.exchange(op, business, lookup), 503, 'UNAVAILABLE')
    elif phase == 'revoked':
        for payload in (business, None):
            denial(client.exchange(op, payload, lookup), 403, 'FORBIDDEN')
