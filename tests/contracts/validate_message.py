"""Structural/context validation ONLY; never authenticates a signature."""
import base64
import binascii
import datetime as dt
import json
import re
import uuid

from validate_boleta import (ROOT, parse_json, validate as validate_boleta,
                             SCHEMA as BOLETA_SCHEMA, ID_FIELDS, CONSTANTS, PATTERNS)
from validate_events import MODEL, validate_event

TYPES = json.loads((ROOT / 'contracts/messages/types.json').read_text(encoding='utf-8'))
SCHEMA = json.loads((ROOT / 'contracts/messages/envelope.schema.json').read_text(encoding='utf-8'))
ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z', re.ASCII)


def exact(obj, required, optional=()):
    if not isinstance(obj, dict) or set(required) - set(obj) or set(obj) - set(required) - set(optional):
        raise ValueError('missing or unknown fields')


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError('invalid identifier')


def uid(value):
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError('noncanonical UUID')
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError('invalid UUID') from exc


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value):
        raise ValueError('UTC timestamp required')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def parse_message(text):
    if len(text.encode('utf-8')) > 256 * 1024:
        raise ValueError('message exceeds 256 KiB')
    try:
        value = parse_json(text)
    except (RecursionError, json.JSONDecodeError) as exc:
        raise ValueError('invalid JSON') from exc
    def walk(node, depth):
        if depth > 32:
            raise ValueError('message exceeds depth 32')
        if isinstance(node, dict):
            for child in node.values():
                walk(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                walk(child, depth + 1)
        elif node is None:
            raise ValueError('null is not an omitted field')
    walk(value, 1)
    return value


def validate_boleta_structure(boleta):
    """Shape only: preserves domain-invalid boleta in authenticated rejection results."""
    exact(boleta, BOLETA_SCHEMA['required'])
    for field in ID_FIELDS:
        identifier(boleta[field])
    for field, expected in CONSTANTS.items():
        if not isinstance(boleta[field], str) or boleta[field] != expected:
            raise ValueError('unsupported boleta enum')
    for field in ('issueRate', 'negotiatedRate', 'quantity', 'unitPrice', 'grossAmount'):
        pattern = PATTERNS[field if field in PATTERNS else 'rate']
        if not isinstance(boleta[field], str) or not pattern.fullmatch(boleta[field]):
            raise ValueError('invalid boleta decimal representation')
    for field in ('tradeDate', 'settlementDate'):
        value = boleta[field]
        if not isinstance(value, str) or dt.date.fromisoformat(value).isoformat() != value:
            raise ValueError('invalid boleta date representation')


def validate_rejection_snapshot(payload):
    state = payload['state']
    if state in ('REJECTED', 'SETTLEMENT_FAILED'):
        if not isinstance(payload.get('reason'), str) or not 1 <= len(payload['reason'].strip()) <= 256:
            raise ValueError('reason required')
    elif 'reason' in payload:
        raise ValueError('unexpected reason')
    if state == 'REJECTED':
        if payload.get('rejectionOrigin') not in ('LOCAL', 'CUSTODIAN'):
            raise ValueError('rejectionOrigin required')
    elif 'rejectionOrigin' in payload:
        raise ValueError('unexpected rejectionOrigin')
    if state == 'REJECTED' and payload['rejectionOrigin'] == 'LOCAL':
        validate_boleta_structure(payload['boleta'])
    else:
        validate_boleta(payload['boleta'], payload['managerId'])


def validate_payload(typ, payload, sender):
    if typ == 'CREATE_OPERATION':
        validate_boleta(payload, sender)
    elif typ.startswith('QUERY_') and typ in TYPES['requests']:
        exact(payload, ())
    elif typ in ('SUBMIT_INSTRUCTION', 'REGISTER_OPERATION'):
        required = ['managerId', 'boleta']
        if typ == 'REGISTER_OPERATION':
            required += ['state', 'sequence']
        exact(payload, required, ('reason', 'rejectionOrigin') if typ == 'REGISTER_OPERATION' else ())
        identifier(payload['managerId'])
        if typ == 'REGISTER_OPERATION':
            if payload['state'] not in MODEL['terminalStates'] or type(payload['sequence']) is not int or payload['sequence'] < 1:
                raise ValueError('terminal snapshot required')
            validate_rejection_snapshot(payload)
        else:
            validate_boleta(payload['boleta'], payload['managerId'])
    elif typ == 'ERROR':
        exact(payload, ('code', 'message', 'correlationId', 'retryable', 'details'))
        identifier(payload['code'])
        uid(payload['correlationId'])
        if not isinstance(payload['message'], str) or not 1 <= len(payload['message']) <= 256 or type(payload['retryable']) is not bool or not isinstance(payload['details'], list):
            raise ValueError('invalid error')
        for detail in payload['details']:
            exact(detail, ('field', 'issue'))
            if any(not isinstance(detail[x], str) or not 1 <= len(detail[x]) <= 256 for x in detail):
                raise ValueError('invalid error detail')
    elif typ == 'SUBMIT_INSTRUCTION_RESULT':
        exact(payload, ('state', 'sequence'))
        if payload['state'] != 'RECEIVED' or type(payload['sequence']) is not int or payload['sequence'] < 1:
            raise ValueError('receipt must represent persistence')
    else:
        exact(payload, ('managerId', 'boleta', 'state', 'sequence'), ('events', 'deliveryStatus', 'reconciliationStatus', 'reason', 'rejectionOrigin'))
        identifier(payload['managerId'])
        if not isinstance(payload['state'], str) or payload['state'] not in MODEL['transitions'] or type(payload['sequence']) is not int or payload['sequence'] < 1:
            raise ValueError('invalid snapshot')
        if typ in ('REGISTER_OPERATION_RESULT', 'QUERY_ADMIN_RECORD_RESULT') and payload['state'] not in MODEL['terminalStates']:
            raise ValueError('administrator snapshot must be terminal')
        if typ == 'CREATE_OPERATION_RESULT' and payload['state'] not in ('REGISTERED', 'VALIDATED', 'REJECTED'):
            raise ValueError('invalid creation result')
        validate_rejection_snapshot(payload)
        if typ == 'CREATE_OPERATION_RESULT' and payload['state'] == 'REJECTED' and payload['rejectionOrigin'] != 'LOCAL':
            raise ValueError('creation rejection must be local')
        if typ in ('QUERY_OPERATION_RESULT', 'QUERY_INSTRUCTION_RESULT') and 'events' not in payload:
            raise ValueError('history required')
        if typ == 'QUERY_OPERATION_RESULT' and not {'deliveryStatus', 'reconciliationStatus'} <= payload.keys():
            raise ValueError('independent statuses required')
        for key, choices in [('deliveryStatus', MODEL['deliveryStatuses']), ('reconciliationStatus', MODEL['reconciliationStatuses'])]:
            if key in payload and payload[key] not in choices:
                raise ValueError('invalid independent status')
        if 'events' in payload:
            if not isinstance(payload['events'], list) or not payload['events']:
                raise ValueError('nonempty history required')
            for event in payload['events']:
                validate_event(event)


def validate_message(message, policy, now, request=None, serialization='JSON'):
    """policy is trusted local input; request is the correlated outbound envelope."""
    exact(message, ('protected', 'payload', 'signatures'))
    p = message['protected']
    definition = SCHEMA['properties']['protected']
    exact(p, definition['required'], ('operationId', 'requestMessageId'))
    if p['schemaVersion'] != '1.0' or type(p['instructionVersion']) is not int or p['instructionVersion'] != 1:
        raise ValueError('unsupported version')
    typ = p['messageType']
    if typ not in TYPES['requests'] + list(TYPES['responses']) + ['ERROR']:
        raise ValueError('unsupported message type')
    if typ not in policy['allowedMessageTypes']:
        raise ValueError('message type not authorized for integration')
    uid(p['messageId'])
    for key in ('senderId', 'recipientId', 'environment'):
        identifier(p[key])
        if p[key] != policy[key]:
            raise ValueError('context incompatible with authenticated integration')
    if type(p['policyVersion']) is not int or p['policyVersion'] != policy['policyVersion']:
        raise ValueError('policy not allowed')
    if p['signatureProfile'] != policy['signatureProfile'] or p['signatureProfile'] not in TYPES['profiles']:
        raise ValueError('profile not allowed')
    if serialization not in ('JSON', 'XML') or p['canonicalization'] != {'JSON': 'JCS', 'XML': 'EXCLUSIVE_C14N_1_0'}[serialization]:
        raise ValueError('canonicalization incompatible')
    issued, expires = timestamp(p['issuedAt']), timestamp(p['expiresAt'])
    if now.tzinfo is None or not 0 < (expires-issued).total_seconds() <= 120 or issued > now + dt.timedelta(seconds=5) or expires < now - dt.timedelta(seconds=5):
        raise ValueError('invalid validity window')
    response = typ in TYPES['responses'] or typ == 'ERROR'
    if response:
        if request is None:
            raise ValueError('response requires outbound request context')
        rp = request['protected']
        uid(p.get('requestMessageId'))
        if p['requestMessageId'] != rp['messageId'] or p['senderId'] != rp['recipientId'] or p['recipientId'] != rp['senderId'] or p['messageId'] == rp['messageId']:
            raise ValueError('response correlation mismatch')
        if typ != 'ERROR' and TYPES['responses'][typ] != rp['messageType']:
            raise ValueError('wrong result type')
        if p['instructionVersion'] != rp['instructionVersion'] or p['environment'] != rp['environment']:
            raise ValueError('response context mismatch')
        if 'operationId' in rp and p.get('operationId') != rp['operationId']:
            raise ValueError('operation correlation mismatch')
    elif 'requestMessageId' in p:
        raise ValueError('request must not include response correlation')
    if typ == 'CREATE_OPERATION':
        if 'operationId' in p:
            raise ValueError('creation has no UUID yet')
    elif typ != 'ERROR' or (request and 'operationId' in request['protected']):
        uid(p.get('operationId'))
    if 'operationId' in p:
        uid(p['operationId'])
    signers, signatures = p['signers'], message['signatures']
    expected = TYPES['profiles'][p['signatureProfile']]
    if not isinstance(signers, list) or not isinstance(signatures, list) or len(signers) != len(expected) or len(signatures) != len(expected):
        raise ValueError('signature count incompatible with profile')
    for index, algorithm in enumerate(expected):
        signer, signature = signers[index], signatures[index]
        exact(signer, ('algorithm', 'keyId'))
        exact(signature, ('algorithm', 'keyId', 'value'))
        identifier(signer['keyId'])
        if signer['algorithm'] != algorithm or any(signature[key] != signer[key] for key in signer):
            raise ValueError('signer/profile/signature mismatch')
        key = policy['trustedKeys'].get(signer['keyId'])
        if not key or key['senderId'] != p['senderId'] or key['algorithm'] != algorithm or key['state'] not in ('ACTIVE', 'VERIFY_ONLY'):
            raise ValueError('key not authorized')
        if not timestamp(key['notBefore']) <= now <= timestamp(key['notAfter']):
            raise ValueError('key outside validity')
        try:
            decoded = base64.b64decode(signature['value'], validate=True)
            if not decoded or base64.b64encode(decoded).decode() != signature['value']:
                raise ValueError('noncanonical base64')
        except (TypeError, binascii.Error) as exc:
            raise ValueError('invalid base64') from exc
    validate_payload(typ, message['payload'], p['senderId'])
    if typ == 'ERROR' and message['payload']['correlationId'] != p['requestMessageId']:
        raise ValueError('error correlation mismatch')
    return {'structurallyValid': True, 'cryptographicallyVerified': False}
