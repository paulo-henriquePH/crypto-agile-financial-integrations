import copy
import json
import unittest

import check_custodian_openapi as c
from validate_message import timestamp


class CustodianContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = json.loads((c.ROOT / 'contracts/messages/examples.json').read_text(encoding='utf-8'))
        cls.cases, cls.now = data['cases'], timestamp(data['referenceNow'])

    def test_contract(self):
        c.check()

    def test_invalid_document(self):
        with self.assertRaises(Exception):
            c.check(True)

    def test_remote_snapshot_mutations(self):
        original = self.cases[7]['message']
        for mutation in ('gap', 'state', 'sequence', 'start', 'version', 'origin', 'duplicate'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                item = copy.deepcopy(original)
                payload = item['payload']
                if mutation == 'gap':
                    payload['events'][1]['sequence'] += 1
                elif mutation == 'state':
                    payload['state'] = 'ACCEPTED'
                elif mutation == 'sequence':
                    payload['sequence'] += 1
                elif mutation == 'start':
                    payload['events'][0] = copy.deepcopy(self.cases[3]['message']['payload']['events'][0])
                elif mutation == 'version':
                    payload['events'][1]['instructionVersion'] = 2
                elif mutation == 'origin':
                    payload['events'][1]['origin'] = 'PLATFORM'
                else:
                    payload['events'][1]['eventId'] = payload['events'][0]['eventId']
                c.history(item)

    def test_path_and_correlation(self):
        msg, policy, query = self.cases[7]['message'], self.cases[7]['policy'], self.cases[6]['message']
        with self.assertRaises(ValueError):
            c.pair(msg, policy, self.now, query, '22222222-2222-4222-8222-222222222222')
        query = copy.deepcopy(query)
        query['protected']['messageId'] = '00000000-0000-4000-8000-000000000155'
        with self.assertRaises(ValueError):
            c.pair(msg, policy, self.now, query)

    def test_timeout_new_query(self):
        fixtures = json.loads((c.ROOT / 'contracts/openapi/custodian-examples.json').read_text(encoding='utf-8'))
        old = self.cases[6]['message']
        old_result = fixtures['decision']
        newer, result, before, after, recovered = c.recovery(self.cases, fixtures, self.now)
        c.pair(old_result, self.cases[7]['policy'], self.now, old)
        with self.assertRaises(ValueError):
            c.pair(old_result, self.cases[7]['policy'], self.now, newer)
        self.assertEqual((before['state'], before['sequence']), (after['state'], after['sequence']))
        self.assertEqual(after['deliveryStatus'], 'UNKNOWN')
        self.assertEqual(recovered, fixtures['recovery']['afterRecovery'])
        self.assertEqual(result['payload']['state'], recovered['state'])

    def test_temporal_rejections(self):
        message = self.cases[7]['message']
        request = self.cases[6]['message']
        for mutation in ('future-event', 'early-response', 'expired-request'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                m, r = copy.deepcopy(message), copy.deepcopy(request)
                if mutation == 'future-event':
                    m['payload']['events'][-1]['occurredAt'] = '2026-11-19T12:00:09Z'
                elif mutation == 'early-response':
                    r['protected']['issuedAt'] = '2026-11-19T12:00:09Z'
                else:
                    r['protected']['expiresAt'] = '2026-11-19T12:00:07Z'
                c.pair(m, self.cases[7]['policy'], self.now, r)

    def test_recovery_rejects_mutations(self):
        original = json.loads((c.ROOT / 'contracts/openapi/custodian-examples.json').read_text(encoding='utf-8'))
        for mutation in ('timeout-state', 'reused-id', 'old-correlation', 'timeout-after-query', 'wrong-applied-state'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                fixtures = copy.deepcopy(original)
                scenario = fixtures['recovery']
                if mutation == 'timeout-state':
                    scenario['afterTimeout']['state'] = 'REJECTED'
                elif mutation == 'reused-id':
                    scenario['newQuery']['messageId'] = self.cases[6]['message']['protected']['messageId']
                elif mutation == 'old-correlation':
                    scenario['newResponse']['requestMessageId'] = self.cases[6]['message']['protected']['messageId']
                elif mutation == 'timeout-after-query':
                    scenario['timeoutAt'] = '2026-11-19T12:00:06Z'
                else:
                    scenario['afterRecovery']['state'] = 'ACCEPTED'
                c.recovery(self.cases, fixtures, self.now)


if __name__ == '__main__':
    unittest.main()
