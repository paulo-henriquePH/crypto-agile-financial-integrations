"""Only called within the authorized attempt's PostgreSQL transaction."""
from hashlib import sha256

from psycopg.types.json import Jsonb
import rfc8785

from services.platform.store import message_receipt, rejection


def owner(db, ref):
    # Include nonexistent records in the critical section. Always lock the
    # operation before its message ID, also for queries and authenticated absence.
    db.execute('SELECT pg_advisory_xact_lock(1,hashtext(%s))', (ref.operation,))
    return db.execute(
        "SELECT snapshot->>'managerId', snapshot->'boleta'->>'portfolioId' FROM operation_snapshots "
        "WHERE operation_id=%s AND instruction_version=1", (ref.operation,)).fetchone()


def allowed(db, ctx, policy_scopes, stored, payload):
    scopes = policy_scopes.intersection(db.execute(
        'SELECT a.manager_id,a.portfolio_id FROM portfolio_access a JOIN portfolio p ON p.id=a.portfolio_id '
        'WHERE p.administrator_id=%s', (ctx.recipient,)).fetchall())
    if not scopes or any(s is not None and s not in scopes for s in (ctx.scope, stored)):
        return False
    return payload is None or payload['boleta']['administratorId'] == ctx.recipient


def fault(ctx, code, message=None, *, retryable=False):
    return 500 if retryable else 400, dict(code=code, message=message or code, details=[],
                                          correlationId=ctx.message, retryable=retryable)


def snapshot(db, operation):
    return db.execute('SELECT snapshot FROM operation_snapshots WHERE operation_id=%s AND instruction_version=1',
                      (operation,)).fetchone()[0]


def register(db, ctx, payload, fits):
    identity = ctx.sender, ctx.recipient, ctx.action, ctx.operation, 1
    # The SOAP projection uses canonical decimal text for sequence. Reuse it
    # both for the existing JCS digest preimage and in JSONB (not a numeric).
    digest = sha256(rfc8785.dumps(payload)).digest()
    prior = db.execute('SELECT digest FROM inbox WHERE '
                       '(sender,recipient,message_type,operation_id,instruction_version)=(%s,%s,%s,%s,%s)',
                       identity).fetchone()
    if prior:
        if prior[0] != digest:
            return fault(ctx, 'IDEMPOTENCY_CONFLICT', 'BUSINESS_DIGEST_MISMATCH')
        return 200, snapshot(db, ctx.operation)
    local_rejection = payload['state'] == 'REJECTED' and payload['rejectionOrigin'] == 'LOCAL'
    if not local_rejection and (reason := rejection(db, payload['boleta'])):
        return fault(ctx, 'INVALID_BUSINESS', reason)
    if not fits(payload):
        return fault(ctx, 'INVALID_BUSINESS', 'SNAPSHOT_RESPONSE_TOO_LARGE')
    db.execute('INSERT INTO operation_snapshots(operation_id,instruction_version,snapshot) VALUES (%s,1,%s)',
               (ctx.operation, Jsonb(payload)))
    db.execute('INSERT INTO inbox(sender,recipient,message_type,operation_id,instruction_version,digest) '
               'VALUES (%s,%s,%s,%s,%s,%s)', (*identity, digest))
    return 200, payload


def apply(db, ctx, payload, wire, *, fits):
    digest = sha256(wire).digest()
    receipt = message_receipt(db, ctx.message)
    if receipt:
        if receipt[0] != digest:
            return fault(ctx, 'IDEMPOTENCY_CONFLICT', 'MESSAGE_ID_REUSED')
        return receipt[1]
    if ctx.error_only == 'NOT_FOUND':
        result = fault(ctx, 'NOT_FOUND')
    elif ctx.action == 'REGISTER_OPERATION':
        result = register(db, ctx, payload, fits)
    else:
        result = 200, snapshot(db, ctx.operation)
    db.execute('INSERT INTO message_receipts(message_id,digest,result) VALUES (%s,%s,%s)',
               (ctx.message, digest, Jsonb(result)))
    return result
