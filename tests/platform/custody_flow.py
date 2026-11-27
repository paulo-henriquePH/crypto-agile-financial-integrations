"""Use actual gestora requests for S2-09, with dates from the S2-08 fixture."""
import json
import sys

from tests.platform.exchanges import B, exchange


LOCAL = ['REGISTERED', 'VALIDATED', 'SENT', 'RECEIVED']


if __name__ == '__main__':
    mode, arg, *states = sys.argv[1:]
    if mode == 'create':
        status, op, body, _ = exchange({**B, 'clientOrderId': arg, 'tradeDate': '2026-11-20',
                                        'settlementDate': '2026-11-23'})
        assert status == 201 and (body['state'], body['sequence']) == ('VALIDATED', 2)
        print(op)
    elif mode == 'receipt-conflict':
        status, _, body, _ = exchange(op=arg, override=dict(messageId=states[0]))
        assert status == 409 and body['code'] == 'IDEMPOTENCY_CONFLICT'
    elif mode == 'history':
        expected_delivery = None
        if states[0].startswith('delivery='):
            expected_delivery = states.pop(0).split('=', 1)[1]
        status, op, body, _ = exchange(op=arg)
        assert status == 200 and op == arg
        history = body['events']
        assert [e['state'] for e in history] == states
        assert [e['sequence'] for e in history] == list(range(1, len(states)+1))
        assert [e.get('previousState') for e in history] == [None, *states[:-1]]
        assert [e['origin'] for e in history] == ['PLATFORM'] * min(len(states), 3) + [
            'CUSTODIAN'] * max(0, len(states)-3)
        assert all(e['operationId'] == op and e['instructionVersion'] == 1 for e in history)
        assert (body['sequence'], body['state']) == (len(states), states[-1])
        assert body['deliveryStatus'] == (expected_delivery or ('CONFIRMED' if len(states) >= 4 else 'PENDING'))
        assert body['reconciliationStatus'] == 'NOT_READY'
        assert body['managerId'] == 'GESTORA-ALFA' and body['boleta']['settlementDate'] == '2026-11-23'
        if body['state'] == 'REJECTED':
            assert (body['reason'], body['rejectionOrigin']) == ('OPERATIONAL_REJECTION', 'CUSTODIAN')
            assert all(body[k] == history[-1][k] for k in ('reason', 'rejectionOrigin'))
        if body['state'] == 'SETTLED':
            assert history[-1]['occurredAt'] == '2026-11-23T00:00:00Z'
        print(json.dumps(history))
    else:
        raise SystemExit('unknown mode')
