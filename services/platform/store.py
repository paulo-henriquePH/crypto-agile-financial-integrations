"""Single transaction per authenticated command. No network I/O inside apply()."""
from datetime import UTC, date, datetime
from decimal import Decimal, ROUND_HALF_UP, localcontext
from hashlib import sha256
from uuid import uuid4

from psycopg.types.json import Jsonb


def stamp():
    return datetime.now(UTC).isoformat().replace('+00:00', 'Z')


def owner(db, ref):
    if ref.client_order is not None:
        # Serialize even when this identity does not yet exist. Recheck visibility
        # after the wait (READ COMMITTED); never consult a prior owner's result.
        db.execute("SELECT pg_advisory_xact_lock(1,hashtext(%s))",
                   (ref.sender + ':' + ref.client_order,))
        return db.execute("SELECT manager_id,boleta->>'portfolioId' FROM operations "
                          "WHERE manager_id=%s AND client_order_id=%s",
                          (ref.sender, ref.client_order)).fetchone()
    return db.execute("SELECT manager_id,boleta->>'portfolioId' FROM operations WHERE id=%s",
                      (ref.operation,)).fetchone()


def rejection(db, b):
    if not db.execute("SELECT 1 FROM portfolio WHERE id=%s AND custodian_id=%s AND administrator_id=%s",
                      (b['portfolioId'], b['custodianId'], b['administratorId'])).fetchone():
        return 'PARTICIPANT_MISMATCH'
    if not db.execute("SELECT 1 FROM asset WHERE id=%s AND issuer_id=%s AND asset_type=%s",
                      (b['assetId'], b['issuerId'], b['assetType'])).fetchone():
        return 'ASSET_MISMATCH'
    if not db.execute("SELECT 1 FROM counterparty WHERE id=%s", (b['counterpartyId'],)).fetchone():
        return 'UNKNOWN_COUNTERPARTY'
    trade, settle = (date.fromisoformat(b[k]) for k in ('tradeDate', 'settlementDate'))
    if settle < trade or max(trade.weekday(), settle.weekday()) >= 5:
        return 'INVALID_DATES'
    with localcontext() as ctx:
        ctx.prec = 40
        gross = (Decimal(b['quantity']) * Decimal(b['unitPrice'])).quantize(Decimal('.01'), ROUND_HALF_UP)
    if gross >= Decimal('1e18'):
        return 'GROSS_AMOUNT_OVERFLOW'
    if gross <= 0 or gross != Decimal(b['grossAmount']):
        return 'GROSS_AMOUNT_MISMATCH'


def error(ctx, status, code):
    return status, ctx.operation, dict(code=code, message=code, correlationId=ctx.message,
                                       retryable=status == 503, details=[])


def create(db, ctx, b):
    row = db.execute("SELECT id,digest FROM operations WHERE manager_id=%s AND client_order_id=%s",
                     (ctx.sender, b['clientOrderId'])).fetchone()
    if row and row[1] != ctx.create_digest:
        return error(ctx, 409, 'IDEMPOTENCY_CONFLICT')
    op = str(row[0] if row else uuid4())
    if not row:
        reason = rejection(db, b)
        db.execute("INSERT INTO operations(id,manager_id,boleta,digest) VALUES (%s,%s,%s,%s)",
                   (op, ctx.sender, Jsonb(b), ctx.create_digest))
        for seq, state in enumerate(('REGISTERED', 'REJECTED' if reason else 'VALIDATED'), 1):
            event = dict(eventId=str(uuid4()), operationId=op, instructionVersion=1,
                         sequence=seq, occurredAt=stamp(), origin='PLATFORM', state=state)
            if seq == 2:
                event.update(previousState='REGISTERED')
                if reason:
                    event.update(reason=reason, rejectionOrigin='LOCAL')
            db.execute("INSERT INTO operation_events(operation_id,event) VALUES (%s,%s)", (op, Jsonb(event)))
        if not reason:
            db.execute("INSERT INTO outbox(operation_id,recipient,message_type,instruction_version,payload) "
                       "VALUES (%s,%s,'SUBMIT_INSTRUCTION',1,%s)",
                       (op, b['custodianId'], Jsonb(dict(managerId=ctx.sender, boleta=b))))
    # Creation is immutable even if the current projection advances later.
    event, = db.execute("SELECT event FROM operation_events WHERE operation_id=%s AND sequence=2",
                        (op,)).fetchone()
    return 200 if row else 201, op, dict(managerId=ctx.sender, boleta=b, **state_fields(event))


def state_fields(event):
    return {k: event[k] for k in ('sequence', 'state', 'reason', 'rejectionOrigin') if k in event}


def snapshot(db, ctx):
    manager, b, delivery, reconciliation, events = db.execute("""
        SELECT manager_id,boleta,delivery_status,reconciliation_status,
               (SELECT jsonb_agg(event ORDER BY sequence) FROM operation_events WHERE operation_id=o.id)
        FROM operations o WHERE id=%s""", (ctx.operation,)).fetchone()
    return 200, ctx.operation, dict(managerId=manager, boleta=b, deliveryStatus=delivery,
                                    reconciliationStatus=reconciliation, events=events, **state_fields(events[-1]))


def message_receipt(db, message_id):
    """Serialize receipt lookup/insertion even before the ID exists."""
    db.execute("SELECT pg_advisory_xact_lock(2,hashtext(%s))", (message_id,))
    return db.execute("SELECT digest,result FROM message_receipts WHERE message_id=%s",
                      (message_id,)).fetchone()


def absence(db, ctx, wire):
    """Reserve authenticated IDs without ever reading a cached snapshot for an absent resource."""
    digest = sha256(wire).digest()
    outcome = error(ctx, 404, 'NOT_FOUND')
    row = message_receipt(db, ctx.message)
    if row and (row[0] != digest or not isinstance(row[1], list)):
        return error(ctx, 409, 'IDEMPOTENCY_CONFLICT')
    if not row:
        db.execute("INSERT INTO message_receipts(message_id,digest,result) VALUES (%s,%s,%s)",
                   (ctx.message, digest, Jsonb(outcome)))
    return outcome


def apply(db, ctx, payload, wire):
    digest = sha256(wire).digest()
    receipt = message_receipt(db, ctx.message)
    if receipt:
        if receipt[0] != digest or not isinstance(receipt[1], list):
            return error(ctx, 409, 'IDEMPOTENCY_CONFLICT')
        status, op, result = receipt[1]
        return (200 if status == 201 else status), op, result
    if ctx.action == 'CREATE_OPERATION':
        result = create(db, ctx, payload)
    else:
        result = snapshot(db, ctx)
    db.execute("INSERT INTO message_receipts(message_id,digest,result) VALUES (%s,%s,%s)",
               (ctx.message, digest, Jsonb(result)))
    return result
