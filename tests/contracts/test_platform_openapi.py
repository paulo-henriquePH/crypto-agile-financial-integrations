import copy
import json
import unittest

from jsonschema import Draft202012Validator
from openapi_spec_validator.validation.exceptions import OpenAPIValidationError

from check_platform_openapi import DOC, ROOT, check, check_pair, check_references, pointer, setup
from validate_message import timestamp


class PlatformOpenAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs, cls.registry, cls.formats = setup()
        cls.corpus = cls.docs[(ROOT / 'contracts/messages/examples.json').as_uri()]
        cls.now = timestamp(cls.corpus['referenceNow'])
        cls.cases = cls.corpus['cases']

    def test_complete_contract(self):
        check()

    def test_invalid_document_fails_real_validator(self):
        with self.assertRaises(OpenAPIValidationError):
            check(invalid=True)

    def test_schema_rejects_version_type_and_unknown_fields(self):
        validator = Draft202012Validator(
            {'$ref': DOC.as_uri() + '#/components/schemas/Create'},
            registry=self.registry, format_checker=self.formats)
        base = self.cases[0]['message']
        for field, value in [('instructionVersion', 2), ('messageType', 'QUERY_OPERATION'),
                             ('operationId', '11111111-1111-4111-8111-111111111111'),
                             ('extra', True)]:
            bad = copy.deepcopy(base)
            bad['protected'][field] = value
            with self.subTest(field=field):
                self.assertFalse(validator.is_valid(bad))

    def test_query_path_and_correlation(self):
        case = self.cases[3]
        request = case['request']
        msg = case['message']
        policy = case['policy']
        op = request['protected']['operationId']
        check_pair(msg, request, policy, self.now, op)
        with self.assertRaises(ValueError):
            check_pair(msg, request, policy, self.now, '22222222-2222-4222-8222-222222222222')
        for field, value in [('requestMessageId', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
                             ('instructionVersion', 2), ('environment', 'OUTRO')]:
            bad = copy.deepcopy(msg)
            bad['protected'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check_pair(bad, request, policy, self.now, op)

    def test_snapshot_history_rejects_gaps_and_operation_swap(self):
        case = self.cases[3]
        op = case['request']['protected']['operationId']
        for kind in ('gap', 'operation', 'state'):
            bad = copy.deepcopy(case['message'])
            if kind == 'gap':
                bad['payload']['events'][1]['sequence'] = 3
            elif kind == 'operation':
                bad['payload']['events'][1]['operationId'] = '22222222-2222-4222-8222-222222222222'
            else:
                bad['payload']['state'] = 'ACCEPTED'
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                check_pair(bad, case['request'], case['policy'], self.now, op)

    def test_creation_boleta_identity_is_not_operation_uuid(self):
        case = self.cases[1]
        for kind in ('clientOrderId', 'amount', 'managerId'):
            bad = copy.deepcopy(case['message'])
            if kind == 'managerId':
                bad['payload'][kind] = 'OUTRA'
            else:
                bad['payload']['boleta'][kind if kind != 'amount' else 'grossAmount'] = (
                    'OTHER' if kind == 'clientOrderId' else '98050.01')
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                check_pair(bad, case['request'], case['policy'], self.now)

    def test_json_pointer_and_duplicates(self):
        self.assertEqual(pointer({'a/b': [7]}, '/a~1b/0'), 7)
        with self.assertRaises(ValueError):
            from check_platform_openapi import unique_pairs
            json.loads('{"x":1,"x":2}', object_pairs_hook=unique_pairs)

    def test_offline_reference_allowlist_and_missing_pointer(self):
        for ref in ('https://example.com/schema', '../../SPEC.md',
                    '#/components/schemas/missing'):
            docs = copy.deepcopy(self.docs)
            docs[DOC.as_uri()]['components']['schemas']['Create']['allOf'][0]['$ref'] = ref
            with self.subTest(ref=ref), self.assertRaises((ValueError, KeyError)):
                check_references(docs)


if __name__ == '__main__':
    unittest.main()
