"""Generate a new public S1-17 corpus in a fresh directory outside the checkout."""

import argparse
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

from lxml import etree

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tests/contracts'))

from verify_signed_vectors import (
    CONFLICT, INTEGRATIONS, PROFILES, REFERENCE_NOW, TYPES, OpenSSL, cases, check_corpus,
    encode64, key_id, key_inventory, parse, read_json,
)
from check_administrator_soap import C, S
from validate_message import BOLETA_SCHEMA

PAYLOAD_SOURCE = {'platform': (0, 1), 'custodian': (4, 5), 'administrator': (8, 9)}
PROTECTED_ORDER = (
    'schemaVersion', 'messageId', 'messageType', 'senderId', 'recipientId', 'environment',
    'operationId', 'instructionVersion', 'issuedAt', 'expiresAt', 'policyVersion',
    'signatureProfile', 'canonicalization', 'signers', 'requestMessageId',
)
OPAQUE_PLACEHOLDER = 'AA=='


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def wire_bytes(logical, format):
    if format == 'JSON':
        return json_bytes(logical)
    root = etree.Element(S + 'Envelope', nsmap={'s': S[1:-1], 'c': C[1:-1]})
    body = etree.SubElement(root, S + 'Body')
    p, payload = logical['protected'], logical['payload']
    parent = body
    if p['messageType'] == 'ERROR':
        fault = etree.SubElement(body, S + 'Fault')
        etree.SubElement(etree.SubElement(fault, S + 'Code'), S + 'Value').text = 's:Sender'
        reason = etree.SubElement(etree.SubElement(fault, S + 'Reason'), S + 'Text',
                                  {'{http://www.w3.org/XML/1998/namespace}lang': 'pt-BR'})
        reason.text = 'Conflito de identidade lógica'
        parent = etree.SubElement(fault, S + 'Detail')
    message = etree.SubElement(parent, C + 'Message')
    content = etree.SubElement(message, C + 'SignedContent')

    def add(parent, name, value):
        element = etree.SubElement(parent, C + name[0].upper() + name[1:])
        if name == 'boleta':
            for field in BOLETA_SCHEMA['required']:
                add(element, field, value[field])
        elif name in ('signers', 'details'):
            child_name = 'Signer' if name == 'signers' else 'Detail'
            for entry in value:
                etree.SubElement(element, C + child_name, entry)
        else:
            element.text = str(value).lower() if type(value) is bool else str(value)

    protected = etree.SubElement(content, C + 'Protected')
    for field in PROTECTED_ORDER:
        if field in p:
            add(protected, field, p[field])
    xml_payload = etree.SubElement(content, C + 'Payload')
    for field, value in payload.items():
        add(xml_payload, field, value)
    signatures = etree.SubElement(message, C + 'Signatures')
    for entry in logical['signatures']:
        etree.SubElement(signatures, C + 'Signature', {
            'algorithm': entry['algorithm'], 'keyId': entry['keyId'],
        }).text = entry['value']
    return etree.tostring(root, encoding='UTF-8') + b'\n'


def message(case, message_id, request, fixtures):
    name, role, profile = case['integration'], case['role'], case['profile']
    integration = INTEGRATIONS[name]
    sender, recipient = integration.direction(role)
    elapsed = '00' if role == 'request' else '08'
    p = {'schemaVersion': '1.0', 'messageId': message_id, 'messageType': integration.kind(role),
         'senderId': sender, 'recipientId': recipient, 'environment': 'LAB',
         'instructionVersion': 1, 'issuedAt': f'2026-11-19T12:00:{elapsed}Z',
         'expiresAt': f'2026-11-19T12:02:{elapsed}Z', 'policyVersion': PROFILES[profile],
         'signatureProfile': profile,
         'canonicalization': 'JCS' if integration.format == 'JSON' else 'EXCLUSIVE_C14N_1_0',
         'signers': [{'algorithm': alg, 'keyId': key_id(sender, alg)}
                     for alg in TYPES['profiles'][profile]]}
    if name != 'platform' or role == 'response':
        p['operationId'] = '11111111-1111-4111-8111-111111111111'
    if request is not None:
        p['requestMessageId'] = request.logical['protected']['messageId']
    if role == 'error':
        payload = {'code': CONFLICT, 'message': 'Conteúdo diferente para a mesma identidade lógica.',
                   'correlationId': p['requestMessageId'], 'retryable': False, 'details': []}
    else:
        index = PAYLOAD_SOURCE[name][role == 'response']
        payload = deepcopy(fixtures[index]['message']['payload'])
    return {'protected': p, 'payload': payload,
            'signatures': [{**signer, 'value': OPAQUE_PLACEHOLDER} for signer in p['signers']]}


def generate(out):
    if out.resolve().is_relative_to(ROOT):
        raise ValueError('output must be outside the checkout')
    crypto = OpenSSL()
    fixtures = read_json(ROOT / 'contracts/messages/examples.json')['cases']
    artifacts, expected, requests = {}, [], {}
    with ExitStack() as owner:
        keys = {identity: owner.enter_context(crypto.generate(identity[1])) for identity in key_inventory()}
        public = [
            {'senderId': sender, 'algorithm': alg, 'keyId': kid, 'state': 'ACTIVE',
             'notBefore': '2026-11-19T00:00:00Z', 'notAfter': '2026-11-20T00:00:00Z',
             'public': encode64(crypto.export_public(keys[(sender, alg, kid)]))}
            for sender, alg, kid in keys
        ]
        for number, case in enumerate(cases(), 1):
            name, role = case['integration'], case['role']
            format = INTEGRATIONS[name].format
            request = requests.get(case['request'])
            logical = message(case, f'00000000-0000-4000-8000-{number:012d}', request, fixtures)
            candidate = parse(wire_bytes(logical, format), name, role, request)
            for entry in logical['signatures']:
                alg = entry['algorithm']
                identity = logical['protected']['senderId'], alg, entry['keyId']
                entry['value'] = encode64(crypto.sign(alg, keys[identity], candidate.canonical))
            wire = wire_bytes(logical, format)
            final = parse(wire, name, role, request)
            if final.canonical != candidate.canonical:
                raise RuntimeError('placing signatures changed the signed bytes')
            if role == 'request':
                requests[Path(case['wire']).stem] = final
            artifacts[case['wire']] = wire
            artifacts[case['canonical']] = (encode64(final.canonical) + '\n').encode('ascii')
            expected.append({**case, 'sha256': hashlib.sha256(final.canonical).hexdigest()})
    # The native private handles have all been released. No private export function is bound.
    out.mkdir(mode=0o700, exist_ok=False)
    artifacts['manifest.json'] = json_bytes({'referenceNow': REFERENCE_NOW, 'vectors': expected})
    artifacts['trust.json'] = json_bytes({'encoding': 'SPKI-DER-Base64', 'keys': public})
    for name, value in artifacts.items():
        with (out / name).open('xb') as stream:
            stream.write(value)
    return len(check_corpus(out, out / 'trust.json'))


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--out', type=Path, required=True)
    args = cli.parse_args()
    try:
        print(f'{generate(args.out)} freshly signed vectors verified with public keys only')
    except (ValueError, RuntimeError, OSError, AttributeError) as exc:
        print(f'S1-17 generator: {exc}', file=sys.stderr)
        raise SystemExit(1) from None
