"""Signed REST witnesses for S2-08; this client has only the platform's identity."""
from datetime import date, timedelta
import json
from pathlib import Path
import sys

from c1.security import Route
from c1.transport import request_headers, receive_response
from services.custodian.client import connection
from exchanges import attempt, client, denial

FIXTURES = Path(__file__).resolve().parents[2] / 'fixtures'
FIXTURE = json.loads((FIXTURES / 'custodian/settlement.json').read_bytes())
BASE = json.loads((FIXTURES / FIXTURE['boletaTemplate']).read_bytes())


def business(op):
    trade = date.fromisoformat(FIXTURE['initialDate'])
    planned = trade + timedelta(days=1)
    while planned.weekday() >= 5:
        planned += timedelta(days=1)
    return dict(managerId=FIXTURE['managerId'], boleta=dict(
        BASE, clientOrderId='S2-08-' + op, tradeDate=str(trade), settlementDate=str(planned)))


def submit(op, payload, lookup):
    with connection() as session:
        prepared = client.prepare(session, op, payload, lookup)
        first = client.send(session, *prepared)
    replay = attempt(prepared)
    assert first[1]['protected']['messageId'] != replay[1]['protected']['messageId']
    for status, response in (first, replay):
        assert status == 202 and response['payload'] == dict(state='RECEIVED', sequence=1)


def snapshot(op, payload, lookup, expected):
    status, response = client.exchange(op, None, lookup)
    p = response['payload']
    assert status == 200 and all(p[key] == value for key, value in payload.items())
    assert len(p['events']) == p['sequence'] == len(expected)
    assert len({e['eventId'] for e in p['events']}) == len(expected)
    for i, (event, spec) in enumerate(zip(p['events'], expected, strict=True), 1):
        state, day = spec.split('@')
        assert event['sequence'] == i and event['operationId'] == op
        assert event['previousState'] == ('SENT' if i == 1 else p['events'][i-2]['state'])
        assert event['state'] == state and event['occurredAt'] == day + 'T00:00:00Z'
        reason = {'REJECTED': 'OPERATIONAL_REJECTION', 'SETTLEMENT_FAILED': 'INSUFFICIENT_CASH'}.get(state)
        assert event.get('reason') == reason
        assert event.get('rejectionOrigin') == ('CUSTODIAN' if state == 'REJECTED' else None)
    last = p['events'][-1]
    assert all(p.get(field) == last.get(field) for field in ('state', 'reason', 'rejectionOrigin'))
    print(f"PASS signed REST history: {' > '.join(e['state'] for e in p['events'])}")


def deny_control(op, lookup):
    assert not Path('/credentials/custodian_runner/password').exists()
    with connection() as session:
        route, wire, ctx = client.prepare(session, op, None, lookup)
        invalid = Route('POST', '/test/settlement/advance', route.media)
        session.link.send(request_headers(invalid, session, wire), wire)
        denial(receive_response(session, client.back, route, ctx), 400, 'INVALID_SCHEMA')


if __name__ == '__main__':
    phase, op, *expected = sys.argv[1:]
    payload = business(op)

    def lookup(_):
        return payload['managerId'], payload['boleta']['portfolioId']

    if phase == 'submit':
        submit(op, payload, lookup)
    elif phase == 'snapshot':
        snapshot(op, payload, lookup, expected)
    elif phase == 'deny-control':
        deny_control(op, lookup)
    else:
        raise ValueError('unknown phase')
