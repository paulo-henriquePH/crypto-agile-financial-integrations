import base64
import importlib.metadata
import json
import unittest

from canonical_xml import (
    CAFI, MAX_BYTES, MAX_DEPTH, VECTORS, XmlRejected, _preflight, _value,
    canonical_message, check_expected, check_vector,
)

CASES = json.loads((VECTORS / 'manifest.json').read_text(encoding='utf-8'))['cases']
BY_NAME = {case['name']: case for case in CASES}


def fixture(name):
    return (VECTORS / BY_NAME[name]['input']).read_bytes()


def replace(data, old, new):
    if old not in data:
        raise AssertionError('invalid test mutation')
    return data.replace(old, new, 1)


class CanonicalXmlTests(unittest.TestCase):
    def test_library_version(self):
        self.assertEqual(importlib.metadata.version('lxml'), '6.1.3')

    def test_static_vectors(self):
        self.assertEqual(len(BY_NAME), len(CASES))
        self.assertEqual({c['input'] for c in CASES}, {p.name for p in VECTORS.glob('*.input.xml')})
        for case in CASES:
            with self.subTest(name=case['name']):
                check_vector(case)

    def test_consume_the_content_checked_against_reference(self):
        for name in ('query', 'query-recontextualized'):
            with self.subTest(name=name):
                # No lookup elsewhere in the envelope or reparse of the C14N.
                content = check_vector(BY_NAME[name])
                protected, payload = content
                self.assertEqual(protected.tag, f'{{{CAFI}}}Protected')
                self.assertEqual(payload.tag, f'{{{CAFI}}}Payload')
                self.assertEqual(_value(protected, 'SenderId'), 'PLATFORM')
                self.assertEqual(_value(protected, 'MessageType'), 'QUERY_ADMIN_RECORD')
        content = check_vector(BY_NAME['error'])
        payload = content.find(f'{{{CAFI}}}Payload')
        self.assertEqual(_value(payload, 'Message'), '  Operação <A> & "B"\r\nline 2 > café  ')
        content = check_vector(BY_NAME['registration'])
        boleta = content[1].find(f'{{{CAFI}}}Boleta')
        self.assertEqual(_value(boleta, 'UnitPrice'), '1000.550000')
        self.assertEqual(_value(boleta, 'GrossAmount'), '2001.10')

    def test_exclusion_and_covered_changes(self):
        data = fixture('query')
        _, original = canonical_message(data)
        _, outside = canonical_message(replace(data, b'Tk9UX0FfU0lHTkFUVVJF', b'VEVTVA=='))
        self.assertEqual(original, outside)
        # A different protected value at the *correct* path is syntactically
        # valid but must not match the bytes checked for the original.
        substitution = replace(data, b'>ADMIN<', b'>OTHER<')
        case = BY_NAME['query']
        expected = base64.b64decode((VECTORS / case['expected']).read_bytes().strip(), validate=True)
        with self.assertRaisesRegex(XmlRejected, '^reference-mismatch$'):
            check_expected(substitution, expected, case['sha256'])
        _, whitespace = canonical_message(replace(data, b'<c:Payload/>', b'<c:Payload> </c:Payload>'))
        _, visible_prefix = canonical_message(
            data.replace(b'xmlns:c=', b'xmlns:v=').replace(b'<c:', b'<v:').replace(b'</c:', b'</v:')
        )
        for changed in (whitespace, visible_prefix):
            self.assertNotEqual(original, changed)

    def test_wrappers_do_not_supply_action_destination_or_alternate_content(self):
        data = fixture('query')
        for old, new, code in [
            (b'<s:Body>', b'<s:Header><c:Action>OTHER</c:Action></s:Header><s:Body>', 'soap-path'),
            (b'<c:Message>', b'<c:Message destination="OTHER">', 'soap-path'),
            (b'<c:SignedContent>', b'<c:SignedContent id="synthetic">', 'xsd'),
            (b'<c:SignedContent>', b'<c:SignedContent/><c:SignedContent>', 'soap-path'),
            (b'<c:SignedContent>', b'<c:Wrapper><c:SignedContent>', 'soap-path'),
            (b'<c:Message>', b'<c:Message>unexpected', 'soap-path'),
        ]:
            with self.subTest(new=new):
                mutated = replace(data, old, new)
                if new.startswith(b'<c:Wrapper>'):
                    mutated = replace(mutated, b'</c:SignedContent>', b'</c:SignedContent></c:Wrapper>')
                with self.assertRaisesRegex(XmlRejected, f'^{code}$'):
                    canonical_message(mutated)

    def test_xsd_rejects_unknown_duplicate_reordered_and_invalid_fields(self):
        data = fixture('query')
        for source, old, new in [
            (data, b'<c:SchemaVersion>1.0</c:SchemaVersion>', b'<c:SchemaVersion/>'),
            (data, b'>1.0<', b'>2.0<'),
            (data, b'<c:Environment>LAB</c:Environment>', b''),
            (data, b'<c:Environment>LAB</c:Environment>', b'<c:Environment>LAB</c:Environment>' * 2),
            (data, b'<c:SenderId>PLATFORM</c:SenderId><c:RecipientId>ADMIN</c:RecipientId>',
             b'<c:RecipientId>ADMIN</c:RecipientId><c:SenderId>PLATFORM</c:SenderId>'),
            (data, b'<c:Payload/>', b'<c:Payload><c:Unknown/></c:Payload>'),
            (data, b'>EXCLUSIVE_C14N_1_0<', b'>JCS<'),
            (data, b'>PLATFORM<', b'> PLATFORM<'),
            (fixture('registration'), b'>2001.10<', b'>2001.1<'),
        ]:
            with self.subTest(new=new), self.assertRaisesRegex(XmlRejected, '^xsd$'):
                canonical_message(replace(source, old, new))

    def test_cross_field_constraints_not_expressible_in_xsd_1_0(self):
        error = fixture('error')
        registration = fixture('registration')
        for source, old, new, code in [
            (error, b'<RequestMessageId>73333333-3333-4333-8333-333333333333</RequestMessageId>',
             b'', 'request-correlation'),
            (error, b'<CorrelationId>73333333-', b'<CorrelationId>77777777-', 'request-correlation'),
            (error, b'<Signature keyId="ADMIN-ML" algorithm="ML-DSA-65">VEVTVA==</Signature>', b'', 'signers'),
            (error, b'<Signature keyId="ADMIN-ML"', b'<Signature keyId="OTHER"', 'signers'),
            (error, b'>VEVTVA==<', b'>VEVTVB==<', 'signature-encoding'),
            (registration, b'>SETTLED<', b'>REJECTED<', 'terminal-state'),
            (registration, b'>REGISTER_OPERATION<', b'>QUERY_ADMIN_RECORD<', 'payload-type'),
            (registration, b'2026-11-19T12:00:05Z', b'2026-11-31T12:00:05Z', 'calendar'),
        ]:
            with self.subTest(new=new), self.assertRaisesRegex(XmlRejected, f'^{code}$'):
                canonical_message(replace(source, old, new))

    def test_resolution_and_context_rejections(self):
        data = fixture('query')
        for old, new, code in [
            (b'<s:Body>', b'<s:Body xml:base="urn:untrusted">', 'context-attribute'),
            (b'<c:Payload/>', b'<c:Payload xmlns:i="http://www.w3.org/2001/XMLSchema-instance" i:nil="true"/>',
             'context-attribute'),
            (b'<s:Body>', b'<?xml-stylesheet href="https://example.invalid/test.xsl"?><s:Body>',
             'processing-instruction'),
            (b'UTF-8', b'UTF-16', 'encoding'),
            (b'1.0', b'1.1', 'encoding'),
            (b'<c:Payload/>', b'<c:Payload>&undefined;</c:Payload>', 'xml-syntax'),
        ]:
            with self.subTest(new=new), self.assertRaisesRegex(XmlRejected, f'^{code}$'):
                canonical_message(replace(data, old, new))
        for non_utf8 in (data.decode('utf-8').encode('utf-16le'), data + b'\xff'):
            with self.assertRaisesRegex(XmlRejected, '^encoding$'):
                canonical_message(non_utf8)
        # Literal markup inside comments is not a DOCTYPE declaration.
        _, original = canonical_message(data)
        _, with_comment = canonical_message(replace(data, b'<c:Payload/>', b'<!--<!DOCTYPE marker>--><c:Payload/>'))
        self.assertEqual(original, with_comment)

    def test_size_and_depth_at_the_limit_and_one_over(self):
        data = fixture('query')
        limit = data + (b' ' * (MAX_BYTES - len(data)))
        self.assertEqual(canonical_message(data)[1], canonical_message(limit)[1])
        # Oversized input fails before parsing even when not XML.
        with self.assertRaisesRegex(XmlRejected, '^size$'):
            canonical_message(b' ' * (MAX_BYTES + 1))

        def nested(depth):
            return b'<n>' * depth + b'</n>' * depth

        # The transport cap counts the root as level one, before the stricter XSD.
        _preflight(nested(MAX_DEPTH))
        with self.assertRaisesRegex(XmlRejected, '^soap-path$'):
            canonical_message(nested(MAX_DEPTH))
        with self.assertRaisesRegex(XmlRejected, '^depth$'):
            canonical_message(nested(MAX_DEPTH + 1))


if __name__ == '__main__':
    unittest.main()
