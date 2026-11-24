"""Offline checks only: no cryptographic verification, transport or persistence."""
import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    '_custodian_common', Path(__file__).with_name('check_platform_openapi.py'))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate as validate_openapi
from validate_events import replay, validate_event
from validate_message import parse_message, timestamp, validate_message

ROOT = common.ROOT
common.DOC = ROOT / 'contracts/openapi/custodian.yaml'
common.FILES = [common.DOC, ROOT / 'contracts/messages/envelope.schema.json',
                ROOT / 'contracts/schemas/boleta.schema.json',
                ROOT / 'contracts/schemas/event.schema.json',
                ROOT / 'contracts/messages/examples.json',
                ROOT / 'contracts/openapi/custodian-examples.json']


def history(message):
    p, payload = message['protected'], message['payload']
    issued = timestamp(p['issuedAt'])
    events = payload['events']
    if not events:
        raise ValueError('empty remote history')
    seen = set()
    previous = 'SENT'
    for seq, event in enumerate(events, 1):
        validate_event(event)
        if timestamp(event['occurredAt']) > issued:
            raise ValueError('event occurs after snapshot issuedAt')
        if (event['sequence'] != seq or event['origin'] != 'CUSTODIAN'
                or event['operationId'] != p['operationId']
                or event['instructionVersion'] != p['instructionVersion']
                or event['previousState'] != previous
                or event['eventId'] in seen):
            raise ValueError('invalid remote event sequence, identity or transition')
        if seq == 1 and event['state'] != 'RECEIVED':
            raise ValueError('remote history must begin RECEIVED')
        seen.add(event['eventId'])
        previous = event['state']
    if (payload['sequence'], payload['state']) != (len(events), previous):
        raise ValueError('snapshot/history mismatch')
    last = events[-1]
    for key in ('reason', 'rejectionOrigin'):
        if payload.get(key) != last.get(key):
            raise ValueError('snapshot reason/origin mismatch')


def pair(message, policy, now, request=None, path=None):
    if path is not None and message['protected']['operationId'] != path:
        raise ValueError('path mismatch')
    validate_message(parse_message(json.dumps(message)), policy, now, request)
    if request is not None:
        issued = timestamp(message['protected']['issuedAt'])
        rp = request['protected']
        if not timestamp(rp['issuedAt']) <= issued <= timestamp(rp['expiresAt']):
            raise ValueError('response outside request timeline')
    if message['protected']['messageType'] == 'QUERY_INSTRUCTION_RESULT':
        history(message)


def recovery(cases, fixtures, now):
    """In-memory example only; remap remote positions to local projection positions."""
    scenario = fixtures['recovery']
    old_query = cases[6]['message']
    submitted = cases[4]['message']
    query = copy.deepcopy(old_query)
    query['protected'].update(scenario['newQuery'])
    response = copy.deepcopy(cases[7]['message'])
    response['protected'].update(scenario['newResponse'])
    timeout_at = timestamp(scenario['timeoutAt'])
    if not (timestamp(submitted['protected']['issuedAt']) <= timeout_at
            and timestamp(old_query['protected']['issuedAt']) <= timeout_at
            < timestamp(query['protected']['issuedAt'])):
        raise ValueError('invalid timeout/query timeline')
    if (query['protected']['messageId'] in
            (old_query['protected']['messageId'], submitted['protected']['messageId'])):
        raise ValueError('new query reuses messageId')
    pair(query, cases[6]['policy'], now)
    pair(response, cases[7]['policy'], now, query)
    local_events = copy.deepcopy(cases[3]['message']['payload']['events'][:3])
    initial = replay(local_events, 'PENDING')
    before = {k: initial[k] for k in ('state', 'sequence', 'deliveryStatus')}
    if before != scenario['beforeTimeout']:
        raise ValueError('incorrect pre-timeout projection')
    # Timeout affects delivery only. Financial projection is replayed unchanged.
    after = replay(local_events, 'UNKNOWN')
    after_timeout = {k: after[k] for k in ('state', 'sequence', 'deliveryStatus')}
    if after_timeout != scenario['afterTimeout'] or any(
            before[k] != after_timeout[k] for k in ('state', 'sequence')):
        raise ValueError('timeout changed financial projection')
    for event in response['payload']['events']:
        event = copy.deepcopy(event)
        event['sequence'] += initial['sequence']
        local_events.append(event)
    applied = replay(local_events, 'CONFIRMED')
    after_recovery = {k: applied[k] for k in ('state', 'sequence', 'deliveryStatus')}
    if after_recovery != scenario['afterRecovery']:
        raise ValueError('recovered local projection mismatch')
    return query, response, before, after_timeout, after_recovery


def check(invalid=False):
    docs, registry, formats = common.setup()
    doc = docs[common.DOC.as_uri()]
    if invalid:
        doc = copy.deepcopy(doc)
        del doc['info']
    validate_openapi(doc, base_uri=common.DOC.as_uri())
    expected = {
        ('/v1/instructions', 'request'): ('Submit', '../messages/examples.json#/cases/4/message'),
        ('/v1/instructions', '202'): ('Receipt', '../messages/examples.json#/cases/5/message'),
        ('/v1/instructions', '409'): ('Error', 'custodian-examples.json#/conflict'),
        ('/v1/instructions/{operationId}/status-queries', 'request'): ('Query', '../messages/examples.json#/cases/6/message'),
        ('/v1/instructions/{operationId}/status-queries', '200'): ('QueryResult', '../messages/examples.json#/cases/7/message'),
        ('/v1/instructions/{operationId}/status-queries', '404'): ('Error', 'custodian-examples.json#/notFound')}
    if set(doc['paths']) != {x[0] for x in expected} or any(set(v) != {'post'} for v in doc['paths'].values()):
        raise ValueError('unexpected paths or methods')
    if doc.get('security') != [{'mutualTLS': []}]:
        raise ValueError('mTLS required')
    corpus = docs[(ROOT / 'contracts/messages/examples.json').as_uri()]
    cases = corpus['cases']
    now = timestamp(corpus['referenceNow'])
    query, submit = cases[6]['message'], cases[4]['message']
    fixtures = docs[(ROOT / 'contracts/openapi/custodian-examples.json').as_uri()]
    conflict = fixtures['conflictRequest']
    identity = ('senderId', 'recipientId', 'messageType', 'operationId', 'instructionVersion')
    if (any(conflict['protected'][k] != submit['protected'][k] for k in identity)
            or conflict['payload'] == submit['payload']
            or conflict['protected']['messageId'] == submit['protected']['messageId']):
        raise ValueError('invalid logical identity conflict')
    terminal = cases[7]['message']['payload']
    receipt = cases[5]['message']['payload']
    if (receipt != {'state': 'RECEIVED', 'sequence': 1}
            or terminal['managerId'] != submit['payload']['managerId']
            or terminal['boleta'] != submit['payload']['boleta']
            or fixtures['decision']['payload']['events'] != terminal['events'][:2]):
        raise ValueError('receipt, decision or snapshot does not match instruction')
    if timestamp(cases[5]['message']['protected']['issuedAt']) < timestamp(terminal['events'][0]['occurredAt']):
        raise ValueError('receipt predates received event')
    recovery(cases, fixtures, now)
    path = query['protected']['operationId']
    refs = []
    for (route, status), (schema, ref) in expected.items():
        operation = doc['paths'][route]['post']
        container = operation['requestBody'] if status == 'request' else operation['responses'][status]
        media = container['content']['application/json']
        if media['schema'] != {'$ref': '#/components/schemas/' + schema}:
            raise ValueError('wrong schema placement')
        expected_refs = ([ref, 'custodian-examples.json#/decision'] if schema == 'QueryResult'
                         else [ref, 'custodian-examples.json#/conflictRequest'] if schema == 'Submit'
                         else [ref])
        if [x['externalValue'] for x in media['examples'].values()] != expected_refs:
            raise ValueError('wrong example placement')
        for example_ref in expected_refs:
            message = common.read_example(example_ref, docs)
            Draft202012Validator({'$ref': common.DOC.as_uri() + '#/components/schemas/' + schema},
                                 registry=registry, format_checker=formats).validate(message)
            index = {'Submit': 4, 'Receipt': 5, 'Query': 6, 'QueryResult': 7, 'Error': 7}[schema]
            policy = copy.deepcopy(cases[index]['policy'])
            if schema == 'Error':
                policy['allowedMessageTypes'] = ['ERROR']
            request = (submit if schema == 'Receipt' else conflict if status == '409'
                       else query if schema in ('QueryResult', 'Error') else None)
            pair(message, policy, now, request, path if route.endswith('status-queries') else None)
            if schema == 'Error' and message['payload']['code'] != ('IDEMPOTENCY_CONFLICT' if status == '409' else 'NOT_FOUND'):
                raise ValueError('wrong error code')
            refs.append(example_ref)
    if len([n for n in common.walk(doc) if 'externalValue' in n]) != len(refs):
        raise ValueError('unchecked example')
    print('OpenAPI custodian: 8 examples, references and remote history validated; signatures illustrative')


def negative(name):
    data = common.load(ROOT / 'contracts/messages/examples.json')
    cases, now = data['cases'], timestamp(data['referenceNow'])
    message = copy.deepcopy(cases[7]['message'])
    request = copy.deepcopy(cases[6]['message'])
    policy = cases[7]['policy']
    path = request['protected']['operationId']
    if name == 'schema':
        docs, registry, formats = common.setup()
        del message['protected']['schemaVersion']
        Draft202012Validator({'$ref': common.DOC.as_uri() + '#/components/schemas/QueryResult'},
                             registry=registry, format_checker=formats).validate(message)
    elif name == 'gap':
        message['payload']['events'][1]['sequence'] += 1
    elif name == 'state':
        message['payload']['state'] = 'ACCEPTED'
    elif name == 'start':
        message['payload']['events'][0] = cases[3]['message']['payload']['events'][0]
    elif name == 'path':
        path = '22222222-2222-4222-8222-222222222222'
    elif name == 'correlation':
        message['protected']['requestMessageId'] = '00000000-0000-4000-8000-000000000155'
    elif name == 'timeout':
        request['protected']['messageId'] = '00000000-0000-4000-8000-000000000155'
    elif name == 'future':
        message['payload']['events'][-1]['occurredAt'] = '2026-11-19T12:00:09Z'
    elif name == 'response-before-request':
        request['protected']['issuedAt'] = '2026-11-19T12:00:09Z'
    pair(message, policy, now, request, path)
    print('negative case unexpectedly accepted', file=sys.stderr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--invalid', action='store_true')
    parser.add_argument('--negative', choices=['schema', 'gap', 'state', 'start', 'path', 'correlation', 'timeout', 'future', 'response-before-request'])
    try:
        args = parser.parse_args()
        if args.negative:
            negative(args.negative)
        else:
            check(args.invalid)
    except Exception as exc:
        print(f'{type(exc).__name__}: {str(exc).splitlines()[0]}', file=sys.stderr)
        raise SystemExit(1) from exc
