"""Caller holds the operation lock from ownership resolution through commit."""
from hashlib import sha256
from uuid import uuid4

import rfc8785
from psycopg.types.json import Jsonb

from services.platform.store import error, message_receipt, stamp, state_fields


def lock_operation(db, operation):
    db.execute('SELECT pg_advisory_xact_lock(1,hashtext(%s))', (operation,))


def owner(db, ref):
    lock_operation(db, ref.operation)
    return db.execute("SELECT payload->>'managerId',payload->'boleta'->>'portfolioId' "
                      "FROM inbox WHERE operation_id=%s", (ref.operation,)).fetchone()


def conflict(ctx, reason):
    status, op, payload = error(ctx, 409, 'IDEMPOTENCY_CONFLICT')
    return status, op, {**payload, 'message': reason}


def append(db, op, sequence, previous, state, day, reason=None):
    event = dict(sequence=sequence, state=state, previousState=previous,
                 eventId=str(uuid4()), operationId=op, instructionVersion=1, origin='CUSTODIAN',
                 occurredAt=f'{day}T00:00:00Z' if day else stamp())
    if reason:
        event['reason'] = reason
    if state == 'REJECTED':
        event['rejectionOrigin'] = 'CUSTODIAN'
    db.execute('INSERT INTO instruction_events(operation_id,event) VALUES (%s,%s)', (op, Jsonb(event)))


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
    # Do not race fixture initialization: a scenario cannot change time basis
    # after its first instruction. Processing does not take this setup lock.
    db.execute('SELECT pg_advisory_xact_lock_shared(208)')
    clock = db.execute('SELECT financial_day FROM settlement_clock').fetchone()
    result = dict(state='RECEIVED', sequence=1)
    db.execute('INSERT INTO inbox VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',
               (*identity, digest, Jsonb(payload), Jsonb(result)))
    append(db, ctx.operation, 1, 'SENT', 'RECEIVED', clock[0] if clock else None)
    return 202, ctx.operation, result


def apply(db, ctx, payload, wire):
    digest = sha256(wire).digest()
    row = message_receipt(db, ctx.message)
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
        result = 200, ctx.operation, dict(**business, events=events, **state_fields(events[-1]))
    db.execute('INSERT INTO message_receipts(message_id,digest,result) VALUES (%s,%s,%s)',
               (ctx.message, digest, Jsonb(result)))
    return result
