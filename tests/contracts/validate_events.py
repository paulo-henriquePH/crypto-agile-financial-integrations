"""Isolated in-memory replay; no worker, persistence or transport."""
import argparse
import datetime as dt
import json
import re
import uuid

from validate_boleta import ROOT, parse_json

MODEL = json.loads((ROOT / 'contracts/domain/transitions.json').read_text(encoding='utf-8'))
SCHEMA = json.loads((ROOT / 'contracts/schemas/event.schema.json').read_text(encoding='utf-8'))


def validate_event(event):
    if not isinstance(event, dict):
        raise ValueError('event must be an object')
    if set(event) - set(SCHEMA['properties']) or set(SCHEMA['required']) - set(event):
        raise ValueError('missing or unknown event field')
    for name in ('eventId', 'operationId'):
        try:
            if str(uuid.UUID(event[name])) != event[name]:
                raise ValueError('UUID must be canonical lowercase')
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('invalid UUID') from exc
    if type(event['instructionVersion']) is not int or event['instructionVersion'] != 1:
        raise ValueError('unsupported instructionVersion')
    if type(event['sequence']) is not int or event['sequence'] < 1:
        raise ValueError('invalid sequence')
    state = event['state']
    if not isinstance(state, str) or state not in MODEL['transitions']:
        raise ValueError('invalid state')
    if event['origin'] not in ('PLATFORM', 'CUSTODIAN'):
        raise ValueError('invalid origin')
    timestamp = event['occurredAt']
    if not isinstance(timestamp, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', timestamp):
        raise ValueError('UTC timestamp required')
    try:
        dt.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('invalid timestamp') from exc
    if state == 'REGISTERED':
        if 'previousState' in event or event['sequence'] != 1 or event['origin'] != 'PLATFORM':
            raise ValueError('invalid initial event')
    else:
        previous = event.get('previousState')
        if not isinstance(previous, str) or previous not in MODEL['transitions']:
            raise ValueError('previousState required')
        if state not in MODEL['transitions'][previous]:
            raise ValueError('forbidden transition')
        expected_origin = 'PLATFORM' if state in ('VALIDATED', 'SENT') or (state == 'REJECTED' and previous == 'REGISTERED') else 'CUSTODIAN'
        if event['origin'] != expected_origin:
            raise ValueError('origin incompatible with transition')
    requires_reason = state in ('REJECTED', 'SETTLEMENT_FAILED')
    if requires_reason != ('reason' in event):
        raise ValueError('reason presence incompatible with state')
    if requires_reason and (not isinstance(event['reason'], str) or not event['reason'].strip() or len(event['reason']) > 256):
        raise ValueError('invalid reason')
    if state == 'REJECTED':
        expected = 'LOCAL' if event['origin'] == 'PLATFORM' else 'CUSTODIAN'
        if event.get('rejectionOrigin') != expected:
            raise ValueError('rejectionOrigin incompatible')
    elif 'rejectionOrigin' in event:
        raise ValueError('unexpected rejectionOrigin')


def replay(events, delivery_status='PENDING', reconciliation_status='NOT_READY'):
    if not isinstance(events, list) or not events:
        raise ValueError('non-empty event list required')
    if delivery_status not in MODEL['deliveryStatuses'] or reconciliation_status not in MODEL['reconciliationStatuses']:
        raise ValueError('invalid independent status')
    by_id, by_sequence = {}, {}
    operation_id, state, sequence, repeated = None, None, 0, 0
    for event in events:
        validate_event(event)
        if operation_id is None:
            operation_id = event['operationId']
        if event['operationId'] != operation_id:
            raise ValueError('operation identity mismatch')
        prior_id = by_id.get(event['eventId'])
        prior_sequence = by_sequence.get(event['sequence'])
        if prior_id is not None or prior_sequence is not None:
            if prior_id == event and prior_sequence == event:
                repeated += 1
                continue
            raise ValueError('conflicting repeated event')
        if event['sequence'] != sequence + 1:
            raise ValueError('sequence gap or regression')
        if state is None:
            if event['state'] != MODEL['initialState']:
                raise ValueError('initial state required')
        elif event.get('previousState') != state:
            raise ValueError('state regression or discontinuity')
        by_id[event['eventId']] = dict(event)
        by_sequence[event['sequence']] = dict(event)
        state, sequence = event['state'], event['sequence']
    return {'operationId': operation_id, 'state': state, 'sequence': sequence,
            'ignoredRepeatedEvents': repeated, 'deliveryStatus': delivery_status,
            'reconciliationStatus': reconciliation_status}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('fixture')
    args = parser.parse_args()
    with open(args.fixture, encoding='utf-8') as stream:
        fixture = parse_json(stream.read())
    print(json.dumps(replay(fixture['events'], fixture.get('deliveryStatus', 'PENDING'),
                            fixture.get('reconciliationStatus', 'NOT_READY')), indent=2))
