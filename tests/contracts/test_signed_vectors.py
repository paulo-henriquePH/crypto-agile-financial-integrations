from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from signed_crypto import BYTE, INT, PTR, SIZE, TEXT, OpenSSLError, PROVIDER_SIGNATURE_FAILURE, ml
from verify_signed_vectors import (
    CORPUS, ECDSA, INTEGRATIONS, ML_DSA, REFERENCE_NOW, Rejected, OpenSSL,
    check_corpus, decode64, encode64, main, parse, read_trust, timestamp, verify,
)


def replace(data, old, new):
    if old not in data:
        raise AssertionError('missing mutation target')
    return data.replace(old, new, 1)


class SignedVectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(os.environ.get('CAFI_SIGNED_TEST_CORPUS', CORPUS))
        trust_path = cls.directory / 'trust.json'
        cls.originals = check_corpus(cls.directory, trust_path)
        cls.crypto = OpenSSL()
        cls.trust = read_trust(trust_path)
        cls.now = timestamp(REFERENCE_NOW)

    def vectors(self):
        for stem, original in self.originals.items():
            name, profile, role = stem.split('-')
            ext = INTEGRATIONS[name].format.lower()
            data = (self.directory / f'{stem}.{ext}').read_bytes()
            request = None if role == 'request' else self.originals[f'{name}-{profile}-request']
            yield stem, data, original, (name, role, profile.upper()), request

    def reject(self, stage, data, args, request, trust=None, now=None):
        with self.assertRaisesRegex(Rejected, '^' + re.escape(stage) + '$'):
            verify(self.crypto, data, *args, self.trust if trust is None else trust,
                   now or self.now, request)

    def test_all_originals(self):
        self.assertEqual(len(self.originals), 27)
        self.assertEqual(sum(len(o.logical['signatures']) for o in self.originals.values()), 36)

    def test_payload_changes_reach_evp_in_every_role(self):
        for stem, data, original, args, request in self.vectors():
            name, role, _ = args
            with self.subTest(vector=stem):
                if role == 'error':
                    data = replace(data, 'Conteúdo diferente'.encode(), 'Conteúdo alterado'.encode())
                elif name == 'custodian' and role == 'response':
                    data = replace(data, b'"sequence": 1', b'"sequence": 2')
                else:
                    data = replace(data, b'OP-000001', b'OP-000009')
                self.reject('signature:' + original.logical['signatures'][0]['algorithm'], data, args, request)

    def test_context_is_signed_and_also_checked_against_local_policy(self):
        for stem, data, original, args, request in self.vectors():
            with self.subTest(vector=stem):
                mid = original.logical['protected']['messageId'].encode()
                self.reject('signature:' + original.logical['signatures'][0]['algorithm'],
                            replace(data, mid, b'00000000-0000-4000-8000-000000009999'),
                            args, request)
                # On an XML response the SOAP checker compares these with the
                # request first; the independent local policy also binds them.
                stage = 'soap-contract' if args[0] == 'administrator' and request else 'policy-context'
                environment = b'<c:Environment>LAB' if args[0] == 'administrator' else b'"environment": "LAB'
                self.reject(stage, replace(data, environment, environment[:-3] + b'OTHER'), args, request)
                recipient = original.logical['protected']['recipientId'].encode()
                marker = b'<c:RecipientId>' if args[0] == 'administrator' else b'"recipientId": "'
                self.reject(stage, replace(data, marker + recipient, marker + b'OTHER'), args, request)
                self.reject('policy-context', data, args, request, now=timestamp('2026-11-19T12:02:14Z'))

    def test_wrong_request_is_not_accepted(self):
        for stem, data, original, args, request in self.vectors():
            if request is None:
                continue
            name, _, profile = args
            other_profile = 'dual' if profile != 'DUAL' else 'ecdsa'
            other = self.originals[f'{name}-{other_profile}-request']
            with self.subTest(vector=stem):
                self.reject('soap-contract' if name == 'administrator' else 'policy-context',
                            data, args, other)

    def test_missing_signature_and_swapped_signature_per_signer(self):
        for stem, data, original, args, request in self.vectors():
            name, role, profile = args
            for index, entry in enumerate(original.logical['signatures']):
                alg = entry['algorithm']
                with self.subTest(vector=stem, algorithm=alg):
                    if name == 'administrator':
                        pattern = (rb'<c:Signature [^>]+>' + re.escape(entry['value'].encode())
                                   + rb'</c:Signature>')
                        removed, count = re.subn(pattern, b'', data)
                        self.assertEqual(count, 1)
                        missing_stage = 'soap-contract'
                    else:
                        logical = deepcopy(original.logical)
                        del logical['signatures'][index]
                        removed = json.dumps(logical).encode()
                        missing_stage = 'policy-context' if profile == 'DUAL' else 'json-schema'
                    self.reject(missing_stage, removed, args, request)
                    if role == 'request':
                        other_profile = ('dual' if profile != 'DUAL'
                                         else 'ecdsa' if alg == ECDSA else 'ml_dsa')
                        donor = self.originals[f'{name}-{other_profile}-request']
                    else:
                        other_role = 'error' if role == 'response' else 'response'
                        donor = self.originals[f'{name}-{profile.lower()}-{other_role}']
                    replacement = next(s['value'] for s in donor.logical['signatures'] if s['algorithm'] == alg)
                    self.assertNotEqual(entry['value'], replacement)
                    self.reject('signature:' + alg, replace(data, entry['value'].encode(), replacement.encode()),
                                args, request)

    def test_wrong_public_key_and_revocation_per_signer(self):
        for stem, data, original, args, request in self.vectors():
            sender = original.logical['protected']['senderId']
            for entry in original.logical['signatures']:
                alg, kid = entry['algorithm'], entry['keyId']
                identity = (sender, alg, kid)
                with self.subTest(vector=stem, algorithm=alg):
                    wrong = next(row['public'] for (participant, a, _), row in self.trust.items()
                                 if participant != sender and a == alg)
                    self.reject('signature:' + alg, data, args, request,
                                trust={**self.trust, identity: {**self.trust[identity], 'public': wrong}})
                    self.reject('policy-context', data, args, request,
                                trust={**self.trust, identity: {**self.trust[identity], 'state': 'REVOKED'}})
                    self.reject('policy-context', data, args, request,
                                trust={key: row for key, row in self.trust.items() if key != identity})

    def test_signer_id_algorithm_and_downgrade(self):
        for stem, data, original, args, request in self.vectors():
            name, role, profile = args
            first = original.logical['signatures'][0]
            # Change both protected and detached keyIds, so the pairing itself still matches.
            kid = first['keyId'].encode()
            self.assertEqual(data.count(kid), 2)
            with self.subTest(vector=stem):
                changed_id = data.replace(kid, b'SUBSTITUTE')
                self.reject('policy-context', changed_id, args, request)
                # Even with the original public key, the changed protected ID
                # cannot verify: the ID is covered, not just checked by policy.
                canonical = parse(changed_id, name, role, request).canonical
                sender = original.logical['protected']['senderId']
                pub = self.trust[(sender, first['algorithm'], first['keyId'])]['public']
                self.assertFalse(self.crypto.verify(first['algorithm'], pub, canonical, decode64(first['value'])))
                alg = first['algorithm'].encode()
                substitute = (ML_DSA if first['algorithm'] == ECDSA else ECDSA).encode()
                boundary = b'<c:Signatures>' if name == 'administrator' else b'"signatures":'
                index = data.index(boundary)
                changed = data[:index] + replace(data[index:], alg, substitute)
                stage = 'soap-contract' if name == 'administrator' else 'policy-context'
                self.reject(stage, changed, args, request)
                if profile == 'ECDSA' and role == 'request':
                    self.reject('policy-context', data, (name, role, 'DUAL'), request)

    def test_json_duplicates_and_embedded_key_rejected(self):
        data = (self.directory / 'platform-dual-request.json').read_bytes()
        args = 'platform', 'request', 'DUAL'
        for old, new in (
            (b'{', b'{"payload":{},'),
            (b'"environment":', b'"environment":"LAB","environment":'),
            (b'"value":', b'"value":"AA==","value":'),
        ):
            with self.subTest(new=new):
                self.reject('json-parse', replace(data, old, new), args, None)
        self.reject('json-schema', replace(data, b'"value":', b'"publicKey":"AA==","value":'), args, None)

    def test_xml_wrapping_xxe_xinclude_and_unsigned_header_rejected(self):
        data = (self.directory / 'administrator-dual-request.xml').read_bytes()
        args = 'administrator', 'request', 'DUAL'
        mutations = [
            b'<!DOCTYPE s:Envelope [<!ENTITY xxe SYSTEM "file:///nonexistent-cafi-s1-17">]>' +
            replace(data, b'OP-000001', b'&xxe;'),
            replace(data, b'<s:Body>', b'<s:Body/><s:Body>'),
            replace(data, b'<c:SignedContent>', b'<c:SignedContent/><c:SignedContent>'),
            replace(data, b'<s:Body>', b'<s:Header><c:Action>Other</c:Action></s:Header><s:Body>'),
            replace(data, b'<c:Signatures>', b'<c:Signatures publicKey="AA==">'),
            replace(data, b'<c:Signatures>', b'<c:Signatures/><c:Signatures>'),
            replace(data, b'<c:Payload>', b'<c:Payload><xi:include href="file:///nonexistent" '
                    b'xmlns:xi="http://www.w3.org/2001/XInclude"/>'),
        ]
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.reject('soap-contract', mutated, args, None)
        # The strict path alone cannot detect well-shaped substitution; EVP must.
        first = data.index(b'<c:SignedContent>')
        last = data.index(b'</c:SignedContent>') + len(b'</c:SignedContent>')
        # Keep request context/shape valid; substitute only its changed SignedContent.
        replacement = replace(data[first:last], b'>SETTLED<', b'>REJECTED<')
        replacement = replace(replacement, b'</c:Sequence>', b'</c:Sequence><c:Reason>Recusada</c:Reason>'
                              b'<c:RejectionOrigin>CUSTODIAN</c:RejectionOrigin>')
        self.reject('signature:' + ECDSA, data[:first] + replacement + data[last:], args, None)

    def test_xml_whitespace_is_signed_and_comment_does_not_split_identity(self):
        data = (self.directory / 'administrator-dual-request.xml').read_bytes()
        args = 'administrator', 'request', 'DUAL'
        self.reject('signature:' + ECDSA, replace(data, b'<c:Payload>', b'<c:Payload> '), args, None)
        result = verify(self.crypto, replace(data, b'>GESTORA-ALFA<', b'>GESTORA<!--split-->-ALFA<'),
                        *args, self.trust, self.now)
        self.assertEqual(result.canonical, self.originals['administrator-dual-request'].canonical)
        self.assertEqual(result.logical['payload']['managerId'], 'GESTORA-ALFA')
        self.assertEqual(result.node.getparent().tag, '{urn:cafi:v1}Message')
        self.assertEqual(result.node.tag, '{urn:cafi:v1}SignedContent')

    def test_fault_consumes_only_signed_error(self):
        original = self.originals['administrator-dual-error']
        data = (self.directory / 'administrator-dual-error.xml').read_bytes()
        changed = replace(data, 'Conflito de identidade lógica'.encode(), b'Metadado divergente')
        actual = verify(self.crypto, changed, 'administrator', 'error', 'DUAL', self.trust, self.now,
                        self.originals['administrator-dual-request'])
        self.assertEqual(actual.logical['payload'], original.logical['payload'])
        self.assertEqual(actual.canonical, original.canonical)

    def test_xml_comment_between_signed_content_and_signatures(self):
        for stem, data, original, args, request in self.vectors():
            if args[0] != 'administrator' or args[2] != 'DUAL':
                continue
            with self.subTest(vector=stem):
                data = replace(data, b'</c:SignedContent><c:Signatures>',
                               b'</c:SignedContent><!--neutral--><c:Signatures>')
                candidate = verify(self.crypto, data, *args, self.trust, self.now, request)
                self.assertEqual(candidate.canonical, original.canonical)
                self.assertEqual(candidate.logical, original.logical)
                self.assertEqual([s['algorithm'] for s in candidate.logical['signatures']], [ECDSA, ML_DSA])

    def test_actual_ecdsa_evp_distinguishes_malformed_der_from_mismatch(self):
        vector = self.originals['platform-ecdsa-request']
        entry, = vector.logical['signatures']
        pub = self.trust[(vector.logical['protected']['senderId'], ECDSA, entry['keyId'])]['public']
        signature = decode64(entry['value'])
        malformed = b'\0' + signature[1:]
        for sig, data, expected in ((malformed, vector.canonical, (-1, ())),
                                    (signature, vector.canonical + b'!', (0, (PROVIDER_SIGNATURE_FAILURE,)))):
            with self.subTest(evp=expected[0]):
                with self.crypto.public(ECDSA, pub) as key, self.crypto.operation(ECDSA, key, False) as (ctx, op):
                    native = self.crypto.bind(op, INT, PTR, BYTE, SIZE, BYTE, SIZE)
                    self.crypto.bind('ERR_clear_error', None)()
                    result = native(ctx, ml.buffer(sig), len(sig), ml.buffer(data), len(data))
                    self.assertEqual((result, self.crypto.error_codes()), expected)
                self.assertFalse(self.crypto.verify(ECDSA, pub, data, sig))
        wire = (self.directory / 'platform-ecdsa-request.json').read_bytes()
        self.reject('signature:' + ECDSA,
                    replace(wire, entry['value'].encode(), encode64(malformed).encode()),
                    ('platform', 'request', 'ECDSA'), None)

    def test_evp_operational_return_fails_verifier_and_cli(self):
        wire = (self.directory / 'platform-ecdsa-request.json').read_bytes()
        native_bind = OpenSSL.bind
        for injected, queued in ((-2, True), (-2, False), (-1, False), (0, True)):
            with self.subTest(evp=injected, queued=queued):
                def bind(crypto, name, *args):
                    if name != 'EVP_DigestVerify':
                        return native_bind(crypto, name, *args)

                    def fault(*_):
                        if queued:
                            # Inject just the failure at the native call boundary.
                            native_bind(crypto, 'ERR_new', None)()
                            native_bind(crypto, 'ERR_set_error', None, INT, INT, TEXT)(6, 134, None)
                        return injected

                    return fault

                with patch.object(OpenSSL, 'bind', bind):
                    with self.assertRaises(OpenSSLError) as caught:
                        verify(self.crypto, wire, 'platform', 'request', 'ECDSA', self.trust, self.now)
                    self.assertEqual(caught.exception.result, injected)
                    self.assertEqual(caught.exception.errors, ((6 << 23) | 134,) if queued else ())
                    # Even the deliberate non-verifying input must report an
                    # operational failure, not the expected signature rejection.
                    stdout, stderr = StringIO(), StringIO()
                    argv = ['verify_signed_vectors.py', '--corpus', str(self.directory),
                            '--trust', str(self.directory / 'trust.json'), '--invalid']
                    with patch('sys.argv', argv), redirect_stdout(stdout), redirect_stderr(stderr):
                        self.assertEqual(main(), 1)
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertIn('operational failure', stderr.getvalue())
                    self.assertNotIn('signature:' + ECDSA, stderr.getvalue())

    def test_openssl_encoding_and_full_message(self):
        vector = self.originals['platform-dual-request']
        p = vector.logical['protected']
        for item in vector.logical['signatures']:
            alg = item['algorithm']
            pub = self.trust[(p['senderId'], alg, item['keyId'])]['public']
            sig = decode64(item['value'])
            with self.subTest(algorithm=alg):
                self.assertFalse(self.crypto.verify(alg, pub, hashlib.sha256(vector.canonical).digest(), sig))
                with self.assertRaisesRegex(ValueError, '^noncanonical public SPKI$'):
                    self.crypto.verify(alg, pub + b'\0', vector.canonical, sig)
                invalid = b'\0' + sig[1:]
                if sig[0] == 0:
                    invalid = b'\1' + sig[1:]
                self.assertFalse(self.crypto.verify(alg, pub, vector.canonical, invalid))
                if alg == ML_DSA:
                    self.assertEqual(len(sig), 3309)
                else:
                    self.assertEqual(sig[0], 0x30)
                    self.assertFalse(self.crypto.verify(alg, pub, vector.canonical, bytes(range(64))))


if __name__ == '__main__':
    unittest.main()
