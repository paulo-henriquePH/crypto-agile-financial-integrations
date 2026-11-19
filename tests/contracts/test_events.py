import copy
import unittest

from validate_events import ROOT, parse_json, replay


class EventTests(unittest.TestCase):
    def test_corpus(self):
        for path in sorted((ROOT / 'fixtures/events').glob('*.json')):
            case = parse_json(path.read_text(encoding='utf-8'))
            with self.subTest(case=case['name']):
                args = (case['events'], case.get('deliveryStatus', 'PENDING'),
                        case.get('reconciliationStatus', 'NOT_READY'))
                if not case['valid']:
                    with self.assertRaises(ValueError):
                        replay(*args)
                else:
                    result = replay(*args)
                    self.assertEqual(result['state'], case['expectedState'])
                    self.assertEqual(result['sequence'], case['expectedSequence'])
                    self.assertEqual(result['ignoredRepeatedEvents'], case.get('expectedRepeated', 0))
                    self.assertEqual(result['deliveryStatus'], args[1])
                    self.assertEqual(result['reconciliationStatus'], args[2])

    def test_structural_and_identity_failures(self):
        events = parse_json((ROOT / 'fixtures/events/settled.json').read_text(encoding='utf-8'))['events']
        for field, value in [('sequence', True), ('instructionVersion', True),
                             ('instructionVersion', 2), ('state', []),
                             ('operationId', '22222222-2222-4222-8222-222222222222'),
                             ('eventId', None), ('unknown', 'field'),
                             ('occurredAt', '2026-02-30T12:00:01Z'),
                             ('occurredAt', '2026-11-19T12:00:01+00:00'),
                             ('reason', 'unexpected')]:
            with self.subTest(field=field, value=value):
                bad = copy.deepcopy(events)
                bad[1][field] = value
                with self.assertRaises(ValueError):
                    replay(bad)
        with self.assertRaises(ValueError):
            replay(events[1:])
        with self.assertRaises(ValueError):
            replay(events, 'TIMEOUT')

    def test_missing_reason_and_repeated_id(self):
        case = parse_json((ROOT / 'fixtures/events/local_rejection.json').read_text(encoding='utf-8'))
        del case['events'][-1]['reason']
        with self.assertRaises(ValueError):
            replay(case['events'])
        case = parse_json((ROOT / 'fixtures/events/settled.json').read_text(encoding='utf-8'))
        case['events'][1]['eventId'] = case['events'][0]['eventId']
        with self.assertRaises(ValueError):
            replay(case['events'])


if __name__ == '__main__':
    unittest.main()
