import copy
import json
import unittest

from validate_message import ROOT, parse_message, validate_message, timestamp

CORPUS = json.loads((ROOT / 'contracts/messages/examples.json').read_text(encoding='utf-8'))
NOW = timestamp(CORPUS['referenceNow'])


class MessageTests(unittest.TestCase):
    def check(self, case):
        return validate_message(parse_message(json.dumps(case['message'])), case['policy'], NOW, case.get('request'))

    def test_examples(self):
        for case in CORPUS['cases']:
            with self.subTest(name=case['name']):
                if case['valid']:
                    self.assertEqual(self.check(case), {'structurallyValid': True, 'cryptographicallyVerified': False})
                else:
                    with self.assertRaises(ValueError):
                        self.check(case)

    def test_context_policy_time_key_and_types(self):
        base = CORPUS['cases'][0]
        for field, value in [('senderId', 'OUTRO'), ('recipientId', 'OUTRO'), ('environment', 'PROD'),
                             ('policyVersion', 2), ('instructionVersion', True), ('signatureProfile', 'DUAL'),
                             ('canonicalization', 'EXCLUSIVE_C14N_1_0'), ('messageId', None),
                             ('expiresAt', '2026-11-19T12:02:01Z'), ('issuedAt', '2026-11-19T12:00:36Z')]:
            with self.subTest(field=field):
                case = copy.deepcopy(base)
                case['message']['protected'][field] = value
                with self.assertRaises(ValueError):
                    self.check(case)
        for mutation in ('revoked', 'wrong_algorithm', 'expired_key', 'forbidden_type', 'malformed_base64'):
            with self.subTest(mutation=mutation):
                case = copy.deepcopy(base)
                key = next(iter(case['policy']['trustedKeys'].values()))
                if mutation == 'revoked': key['state'] = 'REVOKED'
                if mutation == 'wrong_algorithm': key['algorithm'] = 'ML-DSA-65'
                if mutation == 'expired_key': key['notAfter'] = '2026-01-02T00:00:00Z'
                if mutation == 'forbidden_type': case['policy']['allowedMessageTypes'] = []
                if mutation == 'malformed_base64': case['message']['signatures'][0]['value'] = 'A==='
                with self.assertRaises(ValueError): self.check(case)

    def test_response_correlation_and_fresh_queries(self):
        case = copy.deepcopy(CORPUS['cases'][1])
        case['message']['protected']['requestMessageId'] = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        with self.assertRaises(ValueError): self.check(case)
        case = copy.deepcopy(next(c for c in CORPUS['cases'] if c['name'] == 'query_operation_result'))
        case['request']['protected']['messageId'] = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        with self.assertRaises(ValueError): self.check(case)
        case['message']['protected']['requestMessageId'] = case['request']['protected']['messageId']
        self.check(case)

    def test_parser_limits_duplicates_null(self):
        for text in ['{"protected":{},"protected":{}}', '{"x":null}', '{"x":' + '['*33 + '1' + ']'*33 + '}', '{"x":"' + 'a'*(256*1024) + '"}']:
            with self.subTest(length=len(text)):
                with self.assertRaises(ValueError): parse_message(text)

    def test_local_rejection_preserves_invalid_business_data_only(self):
        case = copy.deepcopy(next(c for c in CORPUS['cases'] if c['name'] == 'query_operation_result_local_invalid_amount'))
        original = copy.deepcopy(case['message']['payload']['boleta'])
        self.check(case)
        self.assertEqual(original, case['message']['payload']['boleta'])
        case['message']['payload']['rejectionOrigin'] = 'CUSTODIAN'
        with self.assertRaises(ValueError): self.check(case)
        case['message']['payload']['rejectionOrigin'] = 'LOCAL'
        case['message']['payload']['boleta']['grossAmount'] = 98050.01
        with self.assertRaises(ValueError): self.check(case)


if __name__ == '__main__':
    unittest.main()
