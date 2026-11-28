"""Transactional simulator driven only by the laboratory runner."""
from datetime import date
from decimal import Decimal

from services.platform.store import rejection
from .store import append, lock_operation


def initialize(db, name, fixture, boleta):
    db.execute('SELECT pg_advisory_xact_lock(208)')
    existing = db.execute('SELECT fixture,financial_day FROM settlement_clock').fetchone()
    if existing:
        if existing[0] != name:
            raise ValueError('scenario already initialized with a different fixture')
        return existing[1]
    if db.execute('SELECT 1 FROM inbox LIMIT 1').fetchone():
        raise ValueError('initialize the fixture before submitting instructions')
    if fixture['calendar'] != 'MONDAY_TO_FRIDAY_NO_HOLIDAYS':
        raise ValueError('unsupported settlement calendar')
    case = fixture['scenarios'][name]
    day = date.fromisoformat(fixture['initialDate'])
    db.execute('INSERT INTO settlement_clock(fixture,financial_day,rejection_reason) VALUES (%s,%s,%s)',
               (name, day, case.get('rejectionReason')))
    db.execute('INSERT INTO settlement_cash VALUES (%s,%s,%s)',
               (boleta['portfolioId'], boleta['currency'], Decimal(case['initialCash'])))
    db.execute('INSERT INTO settlement_positions VALUES (%s,%s,%s)',
               (boleta['portfolioId'], boleta['assetId'], int(fixture['initialQuantity'])))
    return day


def clock(db):
    row = db.execute('SELECT financial_day,rejection_reason FROM settlement_clock FOR UPDATE').fetchone()
    if row is None:
        raise ValueError('initialize a fixture first')
    return row


def advance(db, target):
    day, _ = clock(db)
    if target < day:
        raise ValueError('financial clock cannot go backwards')
    if target > day:
        db.execute('UPDATE settlement_clock SET financial_day=%s', (target,))
    return target


def decide(db, b, configured_reason):
    reason = configured_reason or rejection(db, b)
    if not reason and not db.execute("""
            SELECT 1 FROM settlement_cash JOIN settlement_positions USING (portfolio_id)
            WHERE portfolio_id=%s AND currency=%s AND asset_id=%s""",
            (b['portfolioId'], b['currency'], b['assetId'])).fetchone():
        reason = 'UNCONFIGURED_SETTLEMENT_SCOPE'
    return ('REJECTED', reason) if reason else ('ACCEPTED', None)


def settle(db, op, b, day):
    portfolio, currency, asset = (b[k] for k in ('portfolioId', 'currency', 'assetId'))
    amount, quantity = Decimal(b['grossAmount']), int(b['quantity'])
    debit = db.execute("""UPDATE settlement_cash SET balance=balance-%s
        WHERE portfolio_id=%s AND currency=%s AND balance >= %s RETURNING balance""",
        (amount, portfolio, currency, amount)).fetchone()
    if debit is None:
        if db.execute('SELECT 1 FROM settlement_cash WHERE portfolio_id=%s AND currency=%s',
                      (portfolio, currency)).fetchone() is None:
            raise RuntimeError('missing cash account for an accepted operation')
        return 'SETTLEMENT_FAILED', 'INSUFFICIENT_CASH'
    db.execute("""INSERT INTO settlement_entries(operation_id,kind,portfolio_id,currency,amount,effective_date)
                  VALUES (%s,'CASH_DEBIT',%s,%s,%s,%s)""", (op, portfolio, currency, amount, day))
    credit = db.execute("""UPDATE settlement_positions SET quantity=quantity+%s
        WHERE portfolio_id=%s AND asset_id=%s RETURNING quantity""", (quantity, portfolio, asset)).fetchone()
    if credit is None:
        raise RuntimeError('missing asset position for an accepted operation')
    db.execute("""INSERT INTO settlement_entries(operation_id,kind,portfolio_id,asset_id,quantity,effective_date)
                  VALUES (%s,'ASSET_CREDIT',%s,%s,%s,%s)""", (op, portfolio, asset, quantity, day))
    return 'SETTLED', None


def step(db):
    """One transition per visible instruction; clock row serializes runner batches."""
    day, configured_reason = clock(db)
    candidates = db.execute("""SELECT operation_id,payload->'boleta' FROM inbox
        WHERE NOT EXISTS (SELECT 1 FROM instruction_events e WHERE e.operation_id=inbox.operation_id
            AND e.event->>'state' IN ('SETTLED','SETTLEMENT_FAILED','REJECTED'))
        ORDER BY operation_id""").fetchall()
    changed = 0
    for operation, boleta in candidates:
        op = str(operation)
        lock_operation(db, op)
        sequence, previous = db.execute("""SELECT sequence,event->>'state' FROM instruction_events
            WHERE operation_id=%s ORDER BY sequence DESC LIMIT 1""", (op,)).fetchone()
        if previous == 'RECEIVED':
            state, reason = decide(db, boleta, configured_reason)
        elif previous == 'ACCEPTED':
            state, reason = 'PENDING_SETTLEMENT', None
        elif previous == 'PENDING_SETTLEMENT':
            if day.weekday() >= 5 or day < date.fromisoformat(boleta['settlementDate']):
                continue
            state, reason = settle(db, op, boleta, day)
        else:
            raise RuntimeError('unexpected nonterminal instruction state')
        append(db, op, sequence + 1, previous, state, day, reason)
        changed += 1
    return day, changed
