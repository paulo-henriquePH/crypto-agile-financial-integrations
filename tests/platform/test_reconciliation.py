"""Pure comparison tests, not substitutes for the C1 integration tests."""
import unittest

from services.platform.reconciliation import compare


BOLETA = dict(portfolioId='FUNDO-ALFA', assetId='DEB-FICTICIA-01', quantity='100',
              negotiatedRate='6.500000', unitPrice='980.500000', grossAmount='98050.00',
              currency='BRL', settlementDate='2026-11-23')


def inputs():
    return (dict(boleta=BOLETA.copy()),
            dict(boleta=BOLETA.copy(), state='SETTLED', sequence=4,
                 events=[dict(state='SETTLED', occurredAt='2026-11-24T00:00:00Z')]),
            dict(boleta=BOLETA.copy(), state='SETTLED', sequence='4'))


class Reconciliation(unittest.TestCase):
    def test_equal_and_effective_date_not_compared(self):
        self.assertEqual(compare(*inputs()), ('MATCHED', []))

    def test_either_remote_missing(self):
        manager, custodian, administrator = inputs()
        for c, a in ((None, administrator), (custodian, None), (None, None)):
            self.assertEqual(compare(manager, c, a), ('NOT_READY', []))

    def test_each_order_field_and_three_distinct_origins(self):
        different = dict(portfolioId='OTHER', assetId='OTHER', quantity='101', negotiatedRate='6.500001',
                         unitPrice='980.500001', grossAmount='98050.01', currency='USD', settlementDate='2026-11-24')
        for field, value in different.items():
            with self.subTest(field=field):
                manager, custodian, administrator = inputs()
                custodian['boleta'][field] = value
                self.assertEqual(compare(manager, custodian, administrator), ('DIVERGENT', [
                    dict(field=field, values=dict(manager=BOLETA[field], custodian=value, administrator=BOLETA[field]))
                ]))
        manager, custodian, administrator = inputs()
        custodian['boleta']['negotiatedRate'] = '6.500001'
        administrator['boleta']['negotiatedRate'] = '6.500002'
        self.assertEqual(compare(manager, custodian, administrator), ('DIVERGENT', [
            dict(field='negotiatedRate',
                 values=dict(manager='6.500000', custodian='6.500001', administrator='6.500002'))
        ]))

    def test_decimal_without_float_rounding_and_without_lexical_equality(self):
        manager, custodian, administrator = inputs()
        manager['boleta']['grossAmount'] = custodian['boleta']['grossAmount'] = '999999999999999999.98'
        administrator['boleta']['grossAmount'] = '999999999999999999.99'
        administrator['boleta']['negotiatedRate'] = '6.5'
        self.assertEqual(compare(manager, custodian, administrator), ('DIVERGENT', [
            dict(field='grossAmount', values=dict(manager='999999999999999999.98',
                 custodian='999999999999999999.98', administrator='999999999999999999.99'))
        ]))

    def test_terminal_outcome_comes_from_the_remotes_only(self):
        manager, custodian, administrator = inputs()
        self.assertEqual(compare(manager, custodian, administrator), ('MATCHED', []))
        administrator.update(state='REJECTED', reason='OPERATIONAL_REJECTION', rejectionOrigin='CUSTODIAN')
        self.assertEqual(compare(manager, custodian, administrator), ('DIVERGENT', [
            dict(field='state', values=dict(manager=None, custodian='SETTLED', administrator='REJECTED')),
            dict(field='reason', values=dict(manager=None, custodian=None, administrator='OPERATIONAL_REJECTION')),
            dict(field='rejectionOrigin', values=dict(manager=None, custodian=None, administrator='CUSTODIAN'))
        ]))
        custodian.update(state='SETTLEMENT_FAILED', reason='INSUFFICIENT_CASH')
        administrator.update(state='SETTLEMENT_FAILED', reason='INSUFFICIENT_CASH')
        del administrator['rejectionOrigin']
        self.assertEqual(compare(manager, custodian, administrator), ('MATCHED', []))


if __name__ == '__main__':
    unittest.main()
