"""Offline verification of the S1-17 corpus, not a transport or production API."""

import argparse
import base64
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import sys
from xml.parsers import expat

import rfc8785
from jsonschema import Draft202012Validator

import canonical_xml as x
import check_administrator_soap as soap
import check_custodian_openapi as custodian
import check_platform_openapi as platform_api
from canonical_json import canonical_envelope, strict_json
from signed_crypto import ECDSA, ML_DSA, OpenSSL
from validate_message import TYPES, exact, parse_message, timestamp, validate_message

ROOT = x.ROOT
CORPUS = ROOT / 'contracts/vectors/signed/corpus'
REFERENCE_NOW = '2026-11-19T12:00:30Z'
PROFILES = {'ECDSA': 1, 'ML_DSA': 2, 'DUAL': 3}
ROLES = ('request', 'response', 'error')
ENVIRONMENT = 'LAB'
CONFLICT = 'IDEMPOTENCY_CONFLICT'


@dataclass(frozen=True)
class Integration:
    request_type: str
    sender: str
    recipient: str
    route: str
    success: str
    format: str = 'JSON'

    def direction(self, role):
        return (self.sender, self.recipient) if role == 'request' else (self.recipient, self.sender)

    def kind(self, role):
        return {'request': self.request_type,
                'response': self.request_type + '_RESULT',
                'error': 'ERROR'}[role]


INTEGRATIONS = {
    'platform': Integration('CREATE_OPERATION', 'GESTORA-ALFA', 'PLATFORM',
                            '/v1/operations', '201'),
    'custodian': Integration('SUBMIT_INSTRUCTION', 'PLATFORM', 'CUSTODIANTE-GAMA',
                             '/v1/instructions', '202'),
    'administrator': Integration('REGISTER_OPERATION', 'PLATFORM', 'ADMINISTRADOR-DELTA',
                                 soap.ACTION + 'RegisterOperation', 'success', 'XML'),
}


def key_id(sender, algorithm):
    return sender + {ECDSA: '-P256-S117', ML_DSA: '-ML65-S117'}[algorithm]


def key_inventory():
    participants = {participant for i in INTEGRATIONS.values() for participant in i.direction('request')}
    return [(sender, alg, key_id(sender, alg)) for sender in sorted(participants) for alg in (ECDSA, ML_DSA)]


def encode64(data):
    return base64.b64encode(data).decode('ascii')


def decode64(value):
    data = base64.b64decode(value, validate=True)
    if not data or encode64(data) != value:
        raise ValueError('base64')
    return data


def read_json(path):
    return strict_json(path.read_text(encoding='utf-8'))


def read_trust(path):
    """Explicitly configured, out-of-band input; never read from an envelope."""
    document = read_json(path)
    exact(document, ('encoding', 'keys'))
    if document['encoding'] != 'SPKI-DER-Base64':
        raise ValueError('trust encoding')
    records = {}
    for row in document['keys']:
        exact(row, ('senderId', 'algorithm', 'keyId', 'state', 'notBefore', 'notAfter', 'public'))
        identity = row['senderId'], row['algorithm'], row['keyId']
        if identity in records:
            raise ValueError('duplicate trust key')
        records[identity] = {**row, 'public': decode64(row['public'])}
    if set(records) != set(key_inventory()) or len({r['public'] for r in records.values()}) != len(records):
        raise ValueError('trust inventory')
    return records


class Rejected(ValueError):
    """Stable stage for test reporting, without echoing untrusted content."""


@lru_cache(maxsize=None)
def rest_validator(name, role):
    common = platform_api if name == 'platform' else custodian.common
    _, registry, formats = common.setup()
    integration = INTEGRATIONS[name]
    location = ('requestBody' if role == 'request'
                else 'responses/' + ('409' if role == 'error' else integration.success))
    ref = common.DOC.as_uri() + f'#/paths/{integration.route.replace("/", "~1")}/post/{location}'
    return Draft202012Validator({'$ref': ref + '/content/application~1json/schema'},
                                registry=registry, format_checker=formats)


@lru_cache(maxsize=1)
def soap_schema():
    return soap.schema_and_client()[0]


def xml_fields(node):
    """Project an XSD-checked node; consume the same tree, never a reparse."""
    result = {}
    for child in x._children(node):
        name = child.tag[len(soap.C):]
        key = name[0].lower() + name[1:]
        if name == 'Boleta':
            value = xml_fields(child)
        elif name in ('Signers', 'Details'):
            value = [dict(entry.attrib) for entry in x._children(child)]
        else:
            value = x._text(child)
            if name in ('InstructionVersion', 'PolicyVersion', 'Sequence'):
                value = int(value)
            elif name == 'Retryable':
                value = value == 'true'
        result[key] = value
    return result


@dataclass
class Parsed:
    logical: dict
    canonical: bytes
    node: object = None


def parse(data, name, role, request=None):
    integration = INTEGRATIONS[name]
    if len(data) > x.MAX_BYTES:
        raise Rejected('size')
    if integration.format == 'JSON':
        try:
            text = data.decode('utf-8')
            logical = parse_message(text)
            canonical = canonical_envelope(text)
        except (ValueError, RecursionError, rfc8785.CanonicalizationError):
            raise Rejected('json-parse') from None
        if not rest_validator(name, role).is_valid(logical):
            raise Rejected('json-schema')
        return Parsed(logical, canonical)
    schema = soap_schema()
    try:
        content, canonical = soap.check(data, schema, integration.route, integration.kind(role),
                                        None if request is None else request.node)
        protected, payload = x._children(content)
        # The checker validated this exact pair of element children. Ignore
        # intervening comments without reparsing or searching another path.
        _, signatures_node = x._only(content.getparent(), [soap.C + 'SignedContent', soap.C + 'Signatures'])
        signatures = x._children(signatures_node)
        logical = {'protected': xml_fields(protected), 'payload': xml_fields(payload),
                   'signatures': [{**entry.attrib, 'value': x._text(entry)} for entry in signatures]}
    except (ValueError, expat.ExpatError, x.etree.XMLSyntaxError, x.etree.C14NError):
        raise Rejected('soap-contract') from None
    return Parsed(logical, canonical, content)


def verify(crypto, data, name, role, profile, trust, now, request=None):
    """Route, role, profile, trust and clock are supplied by the fixture receiver."""
    integration = INTEGRATIONS[name]
    if (role == 'request') != (request is None):
        raise Rejected('policy-context')
    sender, recipient = integration.direction(role)
    kind = integration.kind(role)
    candidate = parse(data, name, role, request)
    registry = {}
    for alg in TYPES['profiles'][profile]:
        kid = key_id(sender, alg)
        row = trust.get((sender, alg, kid))
        if row is not None:
            registry[kid] = row
    policy = {'senderId': sender, 'recipientId': recipient, 'environment': ENVIRONMENT,
              'allowedMessageTypes': [kind], 'policyVersion': PROFILES[profile],
              'signatureProfile': profile, 'trustedKeys': registry}
    prior = None if request is None else request.logical
    try:
        validate_message(candidate.logical, policy, now, prior, serialization=integration.format)
        if prior is not None:
            p, rp = candidate.logical['protected'], prior['protected']
            if not timestamp(rp['issuedAt']) <= timestamp(p['issuedAt']) <= timestamp(rp['expiresAt']):
                raise ValueError('response outside request timeline')
    except (ValueError, TypeError):
        raise Rejected('policy-context') from None
    for entry in candidate.logical['signatures']:
        alg, kid = entry['algorithm'], entry['keyId']
        try:
            valid = crypto.verify(alg, trust[(sender, alg, kid)]['public'], candidate.canonical,
                                  decode64(entry['value']))
        except ValueError:
            raise Rejected('public-key') from None
        if not valid:
            raise Rejected('signature:' + alg)
    # No returned payload until every signature has passed. Fault Reason/Code are not used here.
    payload = candidate.logical['payload']
    if role == 'error' and (payload['code'] != CONFLICT or payload['retryable']):
        raise Rejected('fixture-semantics')
    if role == 'response':
        if name == 'platform' and (payload['boleta'] != prior['payload']
                                   or payload['managerId'] != prior['protected']['senderId']):
            raise Rejected('fixture-semantics')
        if name == 'administrator' and payload != prior['payload']:
            raise Rejected('fixture-semantics')
    return candidate


def cases():
    for name, integration in INTEGRATIONS.items():
        for profile in PROFILES:
            group = f'{name}-{profile.lower()}'
            for role in ROLES:
                stem = f'{group}-{role}'
                yield {'integration': name, 'profile': profile, 'role': role,
                       'wire': stem + '.' + integration.format.lower(),
                       'canonical': stem + '.canonical.b64',
                       'request': None if role == 'request' else group + '-request',
                       'expected': 'accepted'}


def check_corpus(directory, trust_path, invalid=False):
    crypto = OpenSSL()
    trust = read_trust(trust_path)
    manifest = read_json(directory / 'manifest.json')
    exact(manifest, ('referenceNow', 'vectors'))
    if manifest['referenceNow'] != REFERENCE_NOW:
        raise ValueError('reference clock mismatch')
    now = timestamp(manifest['referenceNow'])
    expected = list(cases())
    if len(manifest['vectors']) != len(expected):
        raise ValueError('corpus inventory')
    parsed, ids = {}, set()
    for case, required in zip(manifest['vectors'], expected):
        exact(case, (*required, 'sha256'))
        if any(case[k] != value for k, value in required.items()):
            raise ValueError('corpus case mismatch')
        name, role, profile = case['integration'], case['role'], case['profile']
        stem = Path(case['wire']).stem
        data = (directory / case['wire']).read_bytes()
        reference = decode64((directory / case['canonical']).read_text(encoding='ascii').removesuffix('\n'))
        request = None if case['request'] is None else parsed[case['request']]
        if invalid:
            # Valid boleta mutation: prove the positive fails in EVP, not just by digest.
            data = data.replace(b'OP-000001', b'OP-000009', 1)
        try:
            candidate = verify(crypto, data, name, role, profile, trust, now, request)
        except Rejected as exc:
            raise ValueError(f'{stem}: {exc}') from None
        if candidate.canonical != reference or hashlib.sha256(candidate.canonical).hexdigest() != case['sha256']:
            raise ValueError(f'{stem}: canonical reference mismatch')
        mid = candidate.logical['protected']['messageId']
        if mid in ids:
            raise ValueError(f'{stem}: duplicate message ID')
        ids.add(mid)
        parsed[stem] = candidate
    return parsed


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--corpus', type=Path, default=CORPUS)
    cli.add_argument('--trust', type=Path, default=CORPUS / 'trust.json')
    cli.add_argument('--invalid', action='store_true', help='perturb the first positive in memory')
    args = cli.parse_args()
    try:
        parsed = check_corpus(args.corpus, args.trust, args.invalid)
    except (ValueError, RuntimeError, OSError, AttributeError) as exc:
        print(f'S1-17: {exc}', file=sys.stderr)
        return 1
    for name in parsed:
        print(f'{name}: accepted (bytes, digest and signatures)')
    print(f'{len(parsed)} signed vectors; reference clock {REFERENCE_NOW}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
