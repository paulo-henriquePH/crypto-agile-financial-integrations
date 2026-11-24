"""Offline OpenAPI and example validation, not signature verification or a server."""
import argparse
import copy
import json
import sys
from pathlib import Path
from urllib.parse import urldefrag, urljoin

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from openapi_spec_validator import validate as validate_openapi

from validate_message import parse_message, timestamp, validate_message, validate_boleta_structure
from validate_events import replay

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / 'contracts/openapi/platform.yaml'
FILES = [DOC, ROOT / 'contracts/messages/envelope.schema.json',
         ROOT / 'contracts/schemas/boleta.schema.json',
         ROOT / 'contracts/schemas/event.schema.json',
         ROOT / 'contracts/messages/examples.json',
         ROOT / 'contracts/openapi/errors.json',
         ROOT / 'contracts/openapi/scenarios.json']


class UniqueLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f'duplicate YAML key: {key}')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def load(path):
    text = path.read_text(encoding='utf-8')
    if path.suffix == '.yaml':
        return yaml.load(text, Loader=UniqueLoader)
    return json.loads(text, object_pairs_hook=unique_pairs)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def pointer(value, fragment):
    if not fragment:
        return value
    if not fragment.startswith('/'):
        raise ValueError('non-pointer fragment')
    for part in fragment[1:].split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def walk(value):
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk(v)


def check_references(docs):
    # Validate every reference in all schemas and the OAS before library use.
    # The allowlist prevents remote URLs, filesystem escape and arbitrary retrieval.
    for path in FILES[:4]:
        base = path.as_uri()
        for node in walk(docs[base]):
            for key in ('$ref', '$dynamicRef', '$recursiveRef', 'externalValue'):
                if key not in node:
                    continue
                ref = node[key]
                if not isinstance(ref, str):
                    raise ValueError('reference must be a string')
                target, fragment = urldefrag(urljoin(base, ref))
                # urljoin does not preserve absolute URNs on all platforms.
                if ref.startswith('urn:'):
                    target, fragment = urldefrag(ref)
                if target not in docs:
                    raise ValueError(f'reference not allowlisted: {ref}')
                pointer(docs[target], fragment)


def setup():
    docs = {p.as_uri(): load(p) for p in FILES}
    for path in FILES[1:4]:
        schema = docs[path.as_uri()]
        Draft202012Validator.check_schema(schema)
        docs[schema['$id']] = schema
    check_references(docs)
    registry = Registry().with_resources(
        (uri, Resource.from_contents(doc, default_specification=DRAFT202012))
        for uri, doc in docs.items()
    )
    checker = FormatChecker()
    if any(x not in checker.checkers for x in ('date', 'date-time', 'uuid')):
        raise RuntimeError('required format checker missing')
    if checker.conforms('2026-02-30T12:00:00Z', 'date-time'):
        raise RuntimeError('date-time checker unavailable')
    return docs, registry, checker


def read_example(ref, docs):
    target, fragment = urldefrag(urljoin(DOC.as_uri(), ref))
    if target not in docs:
        raise ValueError('external example not local')
    return pointer(docs[target], fragment)


def check_pair(message, request, policy, now, path_id=None):
    p = message['protected']
    if path_id is not None and p.get('operationId') != path_id:
        raise ValueError('path and protected operation differ')
    validate_message(parse_message(json.dumps(message)), policy, now, request)
    if request and p['messageType'] == 'CREATE_OPERATION_RESULT':
        if message['payload']['boleta'] != request['payload'] or message['payload']['managerId'] != request['protected']['senderId']:
            raise ValueError('creation snapshot differs from input')
    if p['messageType'] == 'QUERY_OPERATION_RESULT':
        payload = message['payload']
        result = replay(payload['events'], payload['deliveryStatus'], payload['reconciliationStatus'])
        if (result['operationId'], result['state'], result['sequence']) != (p['operationId'], payload['state'], payload['sequence']):
            raise ValueError('snapshot/history mismatch')
        if any(e['instructionVersion'] != p['instructionVersion'] for e in payload['events']):
            raise ValueError('history version mismatch')


def check(invalid=False):
    docs, registry, formats = setup()
    doc = docs[DOC.as_uri()]
    if invalid:
        doc = copy.deepcopy(doc)
        del doc['info']
    validate_openapi(doc, base_uri=DOC.as_uri())
    for schema in doc['components']['schemas'].values():
        Draft202012Validator.check_schema(schema)
    if set(doc['paths']) != {'/v1/operations', '/v1/operations/{operationId}/status-queries'}:
        raise ValueError('unexpected paths')
    if any(set(path) != {'post'} for path in doc['paths'].values()):
        raise ValueError('unexpected methods')
    create_op = doc['paths']['/v1/operations']['post']
    query_op = doc['paths']['/v1/operations/{operationId}/status-queries']['post']
    locations = {
        ('create', 'request'): (create_op['requestBody'], 'Create'),
        ('create', '201'): (create_op['responses']['201'], 'CreateResult'),
        ('create', '200'): (create_op['responses']['200'], 'CreateResult'),
        ('create', '400'): (create_op['responses']['400'], 'Error'),
        ('create', '409'): (create_op['responses']['409'], 'Error'),
        ('query', 'request'): (query_op['requestBody'], 'Query'),
        ('query', '200'): (query_op['responses']['200'], 'QueryResult'),
        ('query', '404'): (query_op['responses']['404'], 'Error'),
    }
    placement = {}
    for location, (container, schema_name) in locations.items():
        media = container['content']['application/json']
        if media['schema'] != {'$ref': '#/components/schemas/' + schema_name}:
            raise ValueError(f'wrong schema at {location}')
        for example in media['examples'].values():
            ref = example['externalValue']
            if ref in placement:
                raise ValueError('duplicate example reference')
            placement[ref] = (location, schema_name)
    expected_placement = {
        '../messages/examples.json#/cases/0/message': ('create', 'request'),
        'scenarios.json#/rejectedRequest': ('create', 'request'),
        'scenarios.json#/replayRequest': ('create', 'request'),
        'scenarios.json#/conflictRequest': ('create', 'request'),
        '../messages/examples.json#/cases/1/message': ('create', '201'),
        '../messages/examples.json#/cases/24/message': ('create', '201'),
        'scenarios.json#/replayResult': ('create', '200'),
        '../messages/examples.json#/cases/12/message': ('create', '400'),
        'errors.json#/conflict': ('create', '409'),
        '../messages/examples.json#/cases/2/message': ('query', 'request'),
        '../messages/examples.json#/cases/3/message': ('query', '200'),
        '../messages/examples.json#/cases/26/message': ('query', '200'),
        'errors.json#/notFound': ('query', '404'),
    }
    if {key: value[0] for key, value in placement.items()} != expected_placement:
        raise ValueError('example attached to wrong operation or status')
    corpus = docs[(ROOT / 'contracts/messages/examples.json').as_uri()]
    scenarios = docs[(ROOT / 'contracts/openapi/scenarios.json').as_uri()]
    errors = docs[(ROOT / 'contracts/openapi/errors.json').as_uri()]
    cases = corpus['cases']
    now = timestamp(corpus['referenceNow'])
    policies = {case['message']['protected']['messageType']: case['policy']
                for case in cases[:4] + [cases[12]]}
    create, query = cases[0]['message'], cases[2]['message']
    path_id = query['protected']['operationId']
    schema_by_type = {'CREATE_OPERATION': 'Create', 'QUERY_OPERATION': 'Query',
                      'CREATE_OPERATION_RESULT': 'CreateResult',
                      'QUERY_OPERATION_RESULT': 'QueryResult', 'ERROR': 'Error'}
    refs = [node['externalValue'] for node in walk(doc) if 'externalValue' in node]
    expected = {'../messages/examples.json#/cases/0/message',
                '../messages/examples.json#/cases/1/message',
                '../messages/examples.json#/cases/2/message',
                '../messages/examples.json#/cases/3/message',
                '../messages/examples.json#/cases/12/message',
                '../messages/examples.json#/cases/24/message',
                '../messages/examples.json#/cases/26/message',
                'errors.json#/conflict', 'errors.json#/notFound',
                'scenarios.json#/rejectedRequest', 'scenarios.json#/replayRequest',
                'scenarios.json#/replayResult', 'scenarios.json#/conflictRequest'}
    if len(refs) != len(expected) or set(refs) != expected:
        raise ValueError('example inventory changed')
    for ref in refs:
        message = read_example(ref, docs)
        typ = message['protected']['messageType']
        if placement[ref][1] != schema_by_type[typ]:
            raise ValueError('example message type incompatible with schema')
        schema = {'$ref': DOC.as_uri() + '#/components/schemas/' + placement[ref][1]}
        Draft202012Validator(schema, registry=registry, format_checker=formats).validate(message)
        if ref.endswith('/rejectedRequest'):
            # It is syntactically valid, but intentionally fails the business check.
            validate_boleta_structure(message['payload'])
            corrected = copy.deepcopy(message)
            corrected['payload']['grossAmount'] = create['payload']['grossAmount']
            check_pair(corrected, None, policies[typ], now)
            try:
                check_pair(message, None, policies[typ], now)
            except ValueError:
                pass
            else:
                raise ValueError('invalid financial amount unexpectedly accepted')
            continue
        request = None
        if typ in ('CREATE_OPERATION_RESULT', 'ERROR', 'QUERY_OPERATION_RESULT'):
            invalid_request = copy.deepcopy(create)
            invalid_request['payload']['quantity'] = '0'
            if Draft202012Validator(
                    {'$ref': DOC.as_uri() + '#/components/schemas/Create'},
                    registry=registry, format_checker=formats).is_valid(invalid_request):
                raise ValueError('invalid syntax request unexpectedly accepted')
            request = (scenarios['rejectedRequest'] if ref.endswith('/24/message') else
                       scenarios['replayRequest'] if ref.endswith('/replayResult') else
                       scenarios['conflictRequest'] if ref.endswith('/conflict') else
                       invalid_request if ref.endswith('/12/message') else
                       query if typ == 'QUERY_OPERATION_RESULT' or ref.endswith('/notFound') else create)
        is_query = typ in ('QUERY_OPERATION', 'QUERY_OPERATION_RESULT') or ref.endswith('/notFound')
        check_pair(message, request, policies[typ], now, path_id if is_query else None)
    if scenarios['replayRequest']['payload'] != create['payload'] or scenarios['replayRequest']['protected']['messageId'] == create['protected']['messageId']:
        raise ValueError('invalid replay fixture')
    conflict = scenarios['conflictRequest']
    if (conflict['protected']['senderId'] != create['protected']['senderId'] or
            conflict['payload']['clientOrderId'] != create['payload']['clientOrderId'] or
            conflict['payload'] == create['payload'] or
            conflict['protected']['messageId'] == create['protected']['messageId']):
        raise ValueError('invalid conflict fixture')
    if scenarios['replayResult']['payload'] != cases[1]['message']['payload'] or scenarios['replayResult']['protected']['operationId'] != cases[1]['message']['protected']['operationId']:
        raise ValueError('replay changed result')
    if errors['conflict']['payload']['code'] != 'IDEMPOTENCY_CONFLICT' or errors['notFound']['payload']['code'] != 'NOT_FOUND':
        raise ValueError('wrong error code')
    for status, message in [('201', cases[1]['message']), ('200', scenarios['replayResult'])]:
        location = create_op['responses'][status]['headers']['Location']['schema']['example']
        if location != '/v1/operations/' + message['protected']['operationId']:
            raise ValueError('Location and protected operation mismatch')
    print(f'OpenAPI 3.1 validado; {len(refs)} exemplos e referências locais verificados; assinaturas ilustrativas')
    return docs


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--invalid', action='store_true')
    try:
        check(parser.parse_args().invalid)
    except Exception as exc:
        print(f'{type(exc).__name__}: {str(exc).splitlines()[0]}', file=sys.stderr)
        raise SystemExit(1) from exc
