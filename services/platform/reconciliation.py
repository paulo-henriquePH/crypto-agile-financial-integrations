"""Exact comparison of records for one operation/version, after source verification."""
from decimal import Decimal


ORDER_FIELDS = ('portfolioId', 'assetId', 'quantity', 'negotiatedRate', 'unitPrice',
                'grossAmount', 'currency', 'settlementDate')
DECIMALS = frozenset(('quantity', 'negotiatedRate', 'unitPrice', 'grossAmount'))
RESULT_FIELDS = ('state', 'reason', 'rejectionOrigin')


def compare(manager, custodian, administrator):
    if custodian is None or administrator is None:
        return 'NOT_READY', []
    differences = []
    for field in ORDER_FIELDS:
        values = dict(manager=manager['boleta'][field], custodian=custodian['boleta'][field],
                      administrator=administrator['boleta'][field])
        if field in DECIMALS:
            equal = len({Decimal(value) for value in values.values()}) == 1
        else:
            equal = len(set(values.values())) == 1
        if not equal:
            differences.append(dict(field=field, values=values))
    for field in RESULT_FIELDS:
        # The order does not predict or originate a settlement outcome.
        if custodian.get(field) != administrator.get(field):
            differences.append(dict(field=field, values=dict(
                manager=None, custodian=custodian.get(field), administrator=administrator.get(field))))
    return ('DIVERGENT' if differences else 'MATCHED'), differences
