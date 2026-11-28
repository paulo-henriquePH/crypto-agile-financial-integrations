"""Exercise only the frozen signed platform REST query, as a real manager."""
import json
import sys

from tests.platform.exchanges import denial, exchange


operation, expected = sys.argv[1:]
response = exchange(op=operation)
if expected == 'FORBIDDEN':
    denial(response, 403, expected)
else:
    status, op, payload, _ = response
    assert (status, op, payload['reconciliationStatus']) == (200, operation, expected)
    assert set(payload) == {'managerId', 'boleta', 'state', 'sequence', 'events',
                            'deliveryStatus', 'reconciliationStatus'}
    print(json.dumps(payload))
