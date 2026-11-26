"""Caller holds the operation lock from ownership resolution through commit."""
from hashlib import sha256
from uuid import uuid4

import rfc8785
from psycopg.types.json import Jsonb

from services.platform.store import error, lock_message, stamp


def owner(db, ref):
    db.execute('SELECT pg_advisory_xact_lock(1,hashtext(%s))', (ref.operation,))
    return db.execute("SELECT payload->>'managerId',payload->'boleta'->>'portfolioId' "
                      "FROM inbox WHERE operation_id=%s", (ref.operation,)).fetchone()


def conflict(ctx, reason):
    status, op, payload = error(ctx, 409, 'IDEMPOTENCY_CONFLICT')
    return status, op, {**payload, 'message': reason}


def submit(db, ctx, payload):
    identity = (ctx.sender, ctx.recipient, ctx.action, ctx.operation, 1)
    digest = sha256(rfc8785.dumps(payload)).digest()
    row = db.execute('SELECT digest,result FROM inbox WHERE '
                     '(sender,recipient,message_type,operation_id,instruction_version)=(%s,%s,%s,%s,%s)',
                     identity).fetchone()
    if row:
        if row[0] != digest:
            return conflict(ctx, 'BUSINESS_DIGEST_MISMATCH')
        return 202, ctx.operation, row[1]
    result = dict(state='RECEIVED', sequence=1)
    db.execute('INSERT INTO inbox VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
               (*identity, digest, Jsonb(payload), Jsonb(result)))
    event = dict(**result, previousState='SENT', eventId=str(uuid4()), operationId=ctx.operation,
                 instructionVersion=1, occurredAt=stamp(), origin='CUSTODIAN')
    db.execute('INSERT INTO instruction_events(operation_id,event) VALUES (%s,%s)', (ctx.operation, Jsonb(event)))
    return 202, ctx.operation, result


def apply(db, ctx, payload, wire):
    lock_message(db, ctx)
    digest = sha256(wire).digest()
    row = db.execute('SELECT digest,result FROM message_receipts WHERE message_id=%s', (ctx.message,)).fetchone()
    if row:
        if row[0] != digest:
            return conflict(ctx, 'MESSAGE_ID_REUSED')
        return row[1]
    if ctx.error_only == 'NOT_FOUND':
        result = error(ctx, 404, 'NOT_FOUND')
    elif ctx.action == 'SUBMIT_INSTRUCTION':
        result = submit(db, ctx, payload)
    else:
        business, events = db.execute('SELECT payload,(SELECT jsonb_agg(event ORDER BY sequence) '
            'FROM instruction_events WHERE operation_id=i.operation_id) FROM inbox i WHERE operation_id=%s',
            (ctx.operation,)).fetchone()
        result = 200, ctx.operation, dict(**business, events=events, state=events[-1]['state'],
                                          sequence=events[-1]['sequence'])
    db.execute('INSERT INTO message_receipts(message_id,digest,result) VALUES (%s,%s,%s)',
               (ctx.message, digest, Jsonb(result)))
    return result
