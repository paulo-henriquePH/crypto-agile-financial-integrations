"""Bound the two SOAP responses to a newly admitted snapshot."""
from base64 import b64encode
from datetime import UTC, datetime

from c1.runtime import body
from c1.soap import envelope

# A P-256 DER signature is a SEQUENCE of two INTEGERs of at most 33 bytes
# (32 bytes and a possible sign byte). With short-form TLVs: 72 bytes / 96 Base64.
MAX_SIGNATURE = b64encode(bytes(2 + 2 * (2 + 33))).decode('ascii')
RESULT_TYPES = ('REGISTER_OPERATION_RESULT', 'QUERY_ADMIN_RECORD_RESULT')
SIZE_TIME = datetime(2000, 1, 1, tzinfo=UTC)
SIZE_ID = '00000000-0000-0000-0000-000000000000'


def response_template(policy, kind, operation, payload, **context):
    # The common signer only replaces this Base64 text; it does not indent or
    # change the tree. Reuse this template for admission and actual emission.
    return envelope(policy, kind, operation, payload, signature=MAX_SIGNATURE, **context)


def fits_snapshot(policy, operation, payload):
    """Bound both emitted SOAP bodies before any new snapshot is persisted."""
    return all(len(response_template(policy, kind, operation, payload, correlation=SIZE_ID,
                                     message_id=SIZE_ID, issued=SIZE_TIME)) <= body.MAX_BYTES
               for kind in RESULT_TYPES)
