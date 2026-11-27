"""Outbox and projection transactions; never open a network connection here."""
import json
from uuid import uuid4

from psycopg.types.json import Jsonb

from c1.runtime import ROOT, require
from .store import stamp


MODEL = json.loads((ROOT / 'contracts/domain/transitions.json').read_bytes())
TRANSITIONS = MODEL['transitions']
TERMINAL = frozenset(MODEL['terminalStates'])
KIND = 'SUBMIT_INSTRUCTION'


def ready(db, recipient):
    return db.execute("""
        SELECT operation_id, attempts=0 FROM outbox
        WHERE recipient=%s AND message_type=%s AND instruction_version=1 AND (
            (attempts=0 AND prepared_envelope IS NULL AND next_attempt_at<=now())
            OR poll_after<=now())
        ORDER BY operation_id""", (recipient, KIND)).fetchall()


def lock(db, op, recipient):
    return db.execute("""
        SELECT q.payload,q.attempts,q.prepared_envelope,q.poll_after<=now(),
               o.manager_id,o.boleta,o.delivery_status
        FROM outbox q JOIN operations o ON o.id=q.operation_id
        WHERE q.operation_id=%s AND q.recipient=%s AND q.message_type=%s
            AND q.instruction_version=1 FOR UPDATE OF q""", (op, recipient, KIND)).fetchone()


def latest(db, op):
    event, = db.execute('SELECT event FROM operation_events WHERE operation_id=%s '
                        'ORDER BY sequence DESC LIMIT 1', (op,)).fetchone()
    return event


def append(db, op, prior, state, *, origin='PLATFORM', fact=None):
    require(state in TRANSITIONS[prior['state']], 'invalid local transition')
    event = {**fact} if fact else dict(eventId=str(uuid4()), operationId=op, instructionVersion=1,
                                     occurredAt=stamp(), origin=origin)
    event.update(state=state, previousState=prior['state'], sequence=prior['sequence']+1)
    db.execute('INSERT INTO operation_events(operation_id,event) VALUES (%s,%s)', (op, Jsonb(event)))
    return event


def prepare(db, op, recipient, signer):
    row = lock(db, op, recipient)
    if row is None or row[1] != 0 or row[2] is not None:
        return
    business, _, _, _, manager, boleta, delivery = row
    prior = latest(db, op)
    require(prior['state'] == 'VALIDATED' and delivery == 'PENDING'
            and business == dict(managerId=manager, boleta=boleta)
            and boleta['custodianId'] == recipient, 'invalid outbox intent')
    prepared = signer(op, business)  # Local C1 signing only.
    db.execute('UPDATE outbox SET prepared_envelope=%s,attempts=1 WHERE operation_id=%s AND recipient=%s '
               'AND message_type=%s AND instruction_version=1', (prepared[1], op, recipient, KIND))
    append(db, op, prior, 'SENT')
    db.execute('UPDATE operations SET updated_at=clock_timestamp() WHERE id=%s', (op,))
    return prepared


def schedule(db, op, recipient, interval):
    db.execute('UPDATE outbox SET poll_after=clock_timestamp()+%s*interval \'1 second\' '
               'WHERE operation_id=%s AND recipient=%s AND message_type=%s AND instruction_version=1',
               (interval, op, recipient, KIND))


def receive(db, op, recipient, prepared_wire, interval):
    row = lock(db, op, recipient)
    require(row is not None and row[1:3] == (1, prepared_wire) and row[-1] == 'PENDING',
            'receipt without matching persisted attempt')
    append(db, op, latest(db, op), 'RECEIVED', origin='CUSTODIAN')
    db.execute("UPDATE operations SET delivery_status='CONFIRMED',updated_at=clock_timestamp() WHERE id=%s",
               (op,))
    schedule(db, op, recipient, interval)


def claim_query(db, op, recipient):
    row = lock(db, op, recipient)
    if row is None or not row[3] or row[-1] != 'CONFIRMED' or latest(db, op)['state'] in TERMINAL:
        return
    # Only a verified successful response can arm another normal poll.
    db.execute('UPDATE outbox SET poll_after=NULL WHERE operation_id=%s AND recipient=%s '
               'AND message_type=%s AND instruction_version=1', (op, recipient, KIND))
    return row[4], row[5]['portfolioId']


def project(db, op, recipient, payload, interval):
    row = lock(db, op, recipient)
    require(row is not None and row[-1] == 'CONFIRMED'
            and payload['managerId'] == row[4] and payload['boleta'] == row[5], 'custody business mismatch')
    applied = [event for event, in db.execute('SELECT event FROM custody_facts WHERE operation_id=%s '
                                              'ORDER BY sequence', (op,))]
    events = payload['events']
    cursor = len(applied)
    require(len(events) >= cursor, 'custody history regression')
    require(events[:cursor] == applied, 'custody history changed')
    prior = latest(db, op)
    initial = prior['sequence']
    # A 202 receipt has no event UUID or financial timestamp. Record the first
    # full remote fact separately when it arrives; never overwrite the receipt.
    for i, fact in enumerate(events[cursor:], cursor+1):
        if i == 1:
            require(prior['state'] == 'RECEIVED', 'missing receipt')
        else:
            require(fact['previousState'] == prior['state'] and
                    (fact['state'] != 'REJECTED' or fact['rejectionOrigin'] == 'CUSTODIAN'),
                    'invalid custody transition')
            prior = append(db, op, prior, fact['state'], fact=fact)
        db.execute('INSERT INTO custody_facts(operation_id,event) VALUES (%s,%s)', (op, Jsonb(fact)))
    if initial != prior['sequence']:
        db.execute('UPDATE operations SET updated_at=clock_timestamp() WHERE id=%s', (op,))
    if prior['state'] not in TERMINAL:
        schedule(db, op, recipient, interval)
    return prior['sequence'] - initial
