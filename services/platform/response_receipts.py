"""Transport response deduplication, independent of financial effects or recovery."""
from psycopg.types.json import Jsonb

from .store import message_receipt


class ResponseMessageConflict(ValueError):
    """A verified response reused a messageId with different bytes or role."""


def register(db, response):
    """Reserve the verified/correlated ID before applying it, in the caller's transaction."""
    p = response.content['protected']
    result = dict(kind='CUSTODY_RESPONSE', status=response.status, messageType=p['messageType'],
                  operationId=p['operationId'], requestMessageId=p['requestMessageId'])
    if p['messageType'] == 'ERROR':
        result['code'] = response.content['payload']['code']
    message_id = p['messageId']
    saved = message_receipt(db, message_id)
    if saved is not None:
        if saved != (response.digest, result):
            raise ResponseMessageConflict('response message ID reused')
        return False
    db.execute('INSERT INTO message_receipts(message_id,digest,result) VALUES (%s,%s,%s)',
               (message_id, response.digest, Jsonb(result)))
    return True
