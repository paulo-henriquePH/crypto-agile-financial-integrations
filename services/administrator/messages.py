"""Local SOAP 1.2 emission, in the element order of the frozen XSD."""
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from lxml import etree

from c1.runtime import ECDSA, body

C, S = body.C, body.S
# A P-256 DER signature is a SEQUENCE of two INTEGERs of at most 33 bytes
# (32 bytes and a possible sign byte). With short-form TLVs: 72 bytes / 96 Base64.
MAX_SIGNATURE = b64encode(bytes(2 + 2 * (2 + 33))).decode('ascii')
RESULT_TYPES = ('REGISTER_OPERATION_RESULT', 'QUERY_ADMIN_RECORD_RESULT')
SIZE_TIME = datetime(2000, 1, 1, tzinfo=UTC)
SIZE_ID = '00000000-0000-0000-0000-000000000000'
BOLETA = ('clientOrderId', 'portfolioId', 'operationType', 'assetType', 'assetId', 'issuerId',
          'counterpartyId', 'tradeDate', 'settlementDate', 'indexer', 'issueRate', 'negotiatedRate',
          'quantity', 'unitPrice', 'grossAmount', 'currency', 'custodianId', 'administratorId')


def child(parent, tag, value=None, **attributes):
    node = etree.SubElement(parent, tag, attrib=attributes)
    node.text = str(value) if value is not None else None
    return node


def emit(parent, values, names):
    for name in names:
        if name in values:
            child(parent, C + name[0].upper() + name[1:], values[name])


def envelope(policy, kind, operation, payload, *, correlation=None, receiver_fault=False,
             issued=None, lifetime=120, message_id=None, signature='AA=='):
    now = datetime.now(UTC) if issued is None else issued
    root = etree.Element(S + 'Envelope', nsmap={'s': S[1:-1], 'c': C[1:-1]})
    parent = child(root, S + 'Body')
    if kind == 'ERROR':
        fault = child(parent, S + 'Fault')
        child(child(fault, S + 'Code'), S + 'Value', 's:Receiver' if receiver_fault else 's:Sender')
        child(child(fault, S + 'Reason'), S + 'Text', 'Request failed',
              **{'{http://www.w3.org/XML/1998/namespace}lang': 'en'})
        parent = child(fault, S + 'Detail')
    message = child(parent, C + 'Message')
    signed = child(message, C + 'SignedContent')
    protected = child(signed, C + 'Protected')
    for name, value in (
        ('SchemaVersion', '1.0'), ('MessageId', message_id or str(uuid4())), ('MessageType', kind),
        ('SenderId', policy.sender), ('RecipientId', policy.recipient), ('Environment', policy.environment),
        ('OperationId', operation), ('InstructionVersion', 1),
        ('IssuedAt', now.isoformat(timespec='microseconds').replace('+00:00', 'Z')),
        ('ExpiresAt', (now + timedelta(seconds=lifetime)).isoformat(timespec='microseconds').replace('+00:00', 'Z')),
        ('PolicyVersion', 1), ('SignatureProfile', 'ECDSA'), ('Canonicalization', 'EXCLUSIVE_C14N_1_0'),
    ):
        child(protected, C + name, value)
    signer = dict(algorithm=ECDSA, keyId=policy.signing_key_id)
    child(child(protected, C + 'Signers'), C + 'Signer', **signer)
    if correlation is not None:
        child(protected, C + 'RequestMessageId', correlation)
    content = child(signed, C + 'Payload')
    if kind == 'ERROR':
        emit(content, payload, ('code', 'message', 'correlationId'))
        child(content, C + 'Retryable', 'true' if payload['retryable'] else 'false')
        details = child(content, C + 'Details')
        for item in payload['details']:
            child(details, C + 'Detail', **item)
    elif payload:
        emit(content, payload, ('managerId',))
        emit(child(content, C + 'Boleta'), payload['boleta'], BOLETA)
        emit(content, payload, ('state', 'sequence', 'reason', 'rejectionOrigin'))
    child(child(message, C + 'Signatures'), C + 'Signature', signature, **signer)
    return etree.tostring(root.getroottree(), encoding='utf-8')


def response_template(policy, kind, operation, payload, **context):
    # The common signer only replaces this Base64 text; it does not indent or
    # change the tree. Reuse this template for admission and actual emission.
    return envelope(policy, kind, operation, payload, signature=MAX_SIGNATURE, **context)


def fits_snapshot(policy, operation, payload):
    """Bound both emitted SOAP bodies before any new snapshot is persisted."""
    return all(len(response_template(policy, kind, operation, payload, correlation=SIZE_ID,
                                    message_id=SIZE_ID, issued=SIZE_TIME)) <= body.MAX_BYTES
               for kind in RESULT_TYPES)
