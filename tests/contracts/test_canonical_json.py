import hashlib
import importlib.metadata
import json
import unittest
from unittest.mock import patch

import rfc8785

from canonical_json import canonical_document, canonical_envelope
from validate_boleta import ROOT

VECTORS = ROOT / 'contracts/vectors/json'
MANIFEST = json.loads((VECTORS / 'manifest.json').read_text(encoding='utf-8'))


class CanonicalJsonTests(unittest.TestCase):
    def test_size_limit_precedes_parsing(self):
        oversized = '{"x":"' + 'a' * (256 * 1024) + '"}'
        with patch('canonical_json.strict_json') as strict_parser, patch('canonical_json.parse_message') as message_parser:
            with self.assertRaisesRegex(ValueError, '256 KiB'):
                canonical_envelope(oversized)
            strict_parser.assert_not_called()
            message_parser.assert_not_called()

    def test_library_version(self):
        self.assertEqual(importlib.metadata.version('rfc8785'), '0.1.4')

    def test_static_vectors(self):
        for case in MANIFEST['cases']:
            with self.subTest(name=case['name']):
                text = (VECTORS / case['input']).read_text(encoding='utf-8')
                canonicalize = canonical_envelope if case['mode'] == 'envelope' else canonical_document
                if case['valid']:
                    expected = (VECTORS / case['expected']).read_bytes()
                    self.assertEqual(hashlib.sha256(expected).hexdigest(), case['sha256'])
                    self.assertEqual(canonicalize(text), expected)
                else:
                    with self.assertRaises(ValueError):
                        canonicalize(text)

    def test_non_json_python_types_rejected_by_library(self):
        for value in ({1: 'not a string key'}, {'x': {1, 2}}, {'x': float('inf')}, {'x': 9007199254740992}):
            with self.subTest(value=repr(value)):
                with self.assertRaises(rfc8785.CanonicalizationError):
                    rfc8785.dumps(value)

    def test_signature_outside_projection_context_inside(self):
        case = next(x for x in MANIFEST['cases'] if x['name'] == 'creation')
        text = (VECTORS / case['input']).read_text(encoding='utf-8')
        before = canonical_envelope(text)
        envelope = json.loads(text)
        envelope['signatures'][0]['value'] = 'VEVTVA=='
        self.assertEqual(before, canonical_envelope(json.dumps(envelope)))
        envelope['protected']['signers'][0]['keyId'] = 'OTHER'
        self.assertNotEqual(before, canonical_envelope(json.dumps(envelope)))


if __name__ == '__main__':
    unittest.main()
