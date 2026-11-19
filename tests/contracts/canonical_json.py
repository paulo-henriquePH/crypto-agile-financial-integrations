"""RFC 8785 library adapter. No cryptographic verification is performed."""
import json

import rfc8785

from validate_message import exact, parse_message

FINANCIAL_STRINGS = {'quantity', 'unitPrice', 'grossAmount', 'issueRate', 'negotiatedRate'}


def strict_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON property')
            result[key] = value
        return result
    def reject_constant(value):
        raise ValueError('non-JSON number: ' + value)
    return json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)


def canonical_document(text):
    return rfc8785.dumps(strict_json(text))


def canonical_envelope(text):
    if len(text.encode('utf-8')) > 256 * 1024:
        raise ValueError('message exceeds 256 KiB')
    # Strict parsing occurs before projection; duplicates in signatures also fail.
    strict_json(text)
    envelope = parse_message(text)
    exact(envelope, ('protected', 'payload', 'signatures'))
    if not isinstance(envelope['protected'], dict) or not isinstance(envelope['payload'], dict) or not isinstance(envelope['signatures'], list):
        raise ValueError('invalid envelope containers')
    if envelope['protected'].get('canonicalization') != 'JCS':
        raise ValueError('JSON requires JCS')
    def financial_strings(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in FINANCIAL_STRINGS and not isinstance(value, str):
                    raise ValueError('financial decimal must remain a string')
                financial_strings(value)
        elif isinstance(node, list):
            for value in node:
                financial_strings(value)
    financial_strings(envelope['payload'])
    return rfc8785.dumps({'protected': envelope['protected'], 'payload': envelope['payload']})
