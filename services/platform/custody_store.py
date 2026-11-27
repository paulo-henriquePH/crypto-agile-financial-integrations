"""Outbox and projection transactions; never open a network connection here."""
from datetime import datetime
import json
from typing import NamedTuple
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from c1.runtime import ROOT, require
from .store import stamp


MODEL = json.loads((ROOT / 'contracts/domain/transitions.json').read_bytes())
TRANSITIONS = MODEL['transitions']
TERMINAL = frozenset(MODEL['terminalStates'])
KIND = 'SUBMIT_INSTRUCTION'
QUERY = 'QUERY_INSTRUCTION'
KEY = "operation_id=%s AND recipient=%s AND message_type='SUBMIT_INSTRUCTION' AND instruction_version=1"


class HistoryGap(ValueError):
    """A verified snapshot omitted facts through this remote sequence."""

    def __init__(self, through):
        super().__init__('custody history gap')
        self.through = through


class Job(NamedTuple):
    payload: dict
    attempts: int
    due: bool
    polling: bool | None
    failures: int
    gap_through: int | None
    authority: UUID | None
    authority_fresh: bool | None
    authority_expires: datetime | None
    manager: str
    boleta: dict
    delivery: str


def reserve(db, op, recipient):
    # Session lock (not a transaction over network I/O). A dead worker loses it
    # and its committed, unfinished attempt stays visible to the next holder.
    return db.execute("SELECT pg_try_advisory_lock(210,hashtext(%s))",
                      (f'{recipient}/{op}',)).fetchone()[0]


def ready(db, recipient):
    return db.execute("""
        SELECT q.operation_id FROM outbox q JOIN operations o ON o.id=q.operation_id
        WHERE q.recipient=%s AND q.message_type=%s AND q.instruction_version=1
        AND o.delivery_status<>'BLOCKED' AND (
            (q.next_attempt_at<=now() AND (o.delivery_status IN ('PENDING','UNKNOWN') OR q.recovery_failures>0))
            OR q.poll_after<=now() OR EXISTS (
                SELECT FROM custody_attempts a WHERE a.operation_id=q.operation_id
                AND a.recipient=q.recipient AND finished_at IS NULL))
        ORDER BY q.operation_id""", (recipient, KIND)).fetchall()


def lock(db, op, recipient):
    row = db.execute("""
        SELECT q.payload,q.attempts,q.next_attempt_at<=now(),q.poll_after<=now(),q.recovery_failures,q.gap_through,
               q.absence_id,q.absence_expires_at>clock_timestamp(),q.absence_expires_at,
               o.manager_id,o.boleta,o.delivery_status
        FROM outbox q JOIN operations o ON o.id=q.operation_id
        WHERE q.operation_id=%s AND q.recipient=%s AND q.message_type=%s
            AND q.instruction_version=1 FOR UPDATE OF q""", (op, recipient, KIND)).fetchone()
    return Job(*row) if row else None


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


def unfinished(db, op, recipient):
    return db.execute('SELECT id,action,request_id FROM custody_attempts '
                      'WHERE operation_id=%s AND recipient=%s AND finished_at IS NULL',
                      (op, recipient)).fetchone()


def action_for(job):
    if job.delivery == 'PENDING' and job.due and job.attempts == 0:
        return KIND
    if job.delivery == 'UNKNOWN' and job.due:
        return KIND if job.authority_fresh else QUERY
    if job.delivery == 'CONFIRMED' and (job.polling or (job.failures and job.due)):
        return QUERY


def begin(db, op, recipient, action, job):
    proof = job.authority if action == KIND and job.authority_fresh else None
    attempt, = db.execute('INSERT INTO custody_attempts(operation_id,recipient,action,authority_id) '
                          'VALUES (%s,%s,%s,%s) RETURNING id', (op, recipient, action, proof)).fetchone()
    db.execute(f'UPDATE outbox SET poll_after=NULL,absence_id=NULL,absence_expires_at=NULL WHERE {KEY}',
               (op, recipient))
    return attempt


def check_intent(job, recipient):
    require(job.payload == dict(managerId=job.manager, boleta=job.boleta)
            and job.boleta['custodianId'] == recipient, 'invalid outbox intent')


def submitted(db, op, recipient, job, attempt, prepared):
    prior = latest(db, op)
    require((job.attempts == 0 and prior['state'] == 'VALIDATED' and job.delivery == 'PENDING')
            or (job.attempts > 0 and prior['state'] == 'SENT' and job.delivery == 'UNKNOWN'
                and job.authority_fresh), 'submit without authority')
    db.execute('UPDATE custody_attempts SET request_id=%s,prepared_envelope=%s WHERE id=%s',
               (prepared.context.message, prepared.wire, attempt))
    db.execute(f'UPDATE outbox SET prepared_envelope=%s,attempts=attempts+1 WHERE {KEY}',
               (prepared.wire, op, recipient))
    if job.attempts == 0:
        append(db, op, prior, 'SENT')
        db.execute('UPDATE operations SET updated_at=clock_timestamp() WHERE id=%s', (op,))


def query_signed(db, attempt, request_id):
    db.execute('UPDATE custody_attempts SET request_id=%s WHERE id=%s', (request_id, attempt))


def finish(db, attempt, outcome, *, code=None, response=None, delay=None):
    return db.execute('UPDATE custody_attempts SET finished_at=clock_timestamp(),outcome=%s,code=%s,'
                      'response_id=%s,retry_delay_seconds=%s WHERE id=%s RETURNING finished_at',
                      (outcome, code, response, delay, attempt)).fetchone()[0]


def fail(db, op, recipient, job, attempt, code, *, retry, delays, response, gap_through):
    failures = job.failures + int(retry)
    delay = delays(failures) if retry else None
    delivery = ('BLOCKED' if not retry or failures == 5 else
                'CONFIRMED' if job.delivery == 'CONFIRMED' else 'UNKNOWN')
    finished = finish(db, attempt, 'BLOCKED' if delivery == 'BLOCKED' else 'RETRY',
                      code=code, delay=delay, response=response)
    db.execute(f"""UPDATE outbox SET recovery_failures=%s,
                gap_through=GREATEST(gap_through,%s::bigint),
                next_attempt_at=%s::timestamptz+%s*interval '1 second' WHERE {KEY}""",
               (failures, gap_through, finished, delay or 0, op, recipient))
    set_delivery(db, op, delivery)
    return delivery, delay


def set_delivery(db, op, delivery):
    db.execute('UPDATE operations SET delivery_status=%s,updated_at=clock_timestamp() '
               'WHERE id=%s AND delivery_status<>%s', (delivery, op, delivery))


def allow_submit(db, op, recipient, proof_id, expires):
    db.execute(f'UPDATE outbox SET absence_id=%s,absence_expires_at=%s,'
               f'next_attempt_at=clock_timestamp() WHERE {KEY}', (proof_id, expires, op, recipient))


def schedule(db, op, recipient, interval):
    db.execute(f'UPDATE outbox SET recovery_failures=0,gap_through=NULL,'
               f"poll_after=clock_timestamp()+%s::double precision*interval '1 second' WHERE {KEY}",
               (interval, op, recipient))


def receive(db, op, recipient, interval):
    append(db, op, latest(db, op), 'RECEIVED', origin='CUSTODIAN')
    set_delivery(db, op, 'CONFIRMED')
    schedule(db, op, recipient, interval)


def project(db, op, recipient, job, payload, interval):
    require(payload['managerId'] == job.manager and payload['boleta'] == job.boleta, 'custody business mismatch')
    applied = [event for event, in db.execute('SELECT event FROM custody_facts WHERE operation_id=%s '
                                              'ORDER BY sequence', (op,))]
    events = payload['events']
    cursor = len(applied)
    last = payload['sequence']
    require(last >= cursor, 'custody history regression')
    require(all(e == applied[e['sequence']-1] for e in events if e['sequence'] <= cursor),
            'custody history changed')
    horizon = job.gap_through or 0
    if last < horizon or len(events) != last or any(e['sequence'] != i for i, e in enumerate(events, 1)):
        raise HistoryGap(max(last, horizon))
    prior = latest(db, op)
    initial = prior['sequence']
    # A full history can prove reception even when the 202 never arrived.
    for i, fact in enumerate(events[cursor:], cursor+1):
        if i == 1:
            if job.delivery == 'UNKNOWN':
                prior = append(db, op, prior, 'RECEIVED', fact=fact)
            else:
                require(prior['state'] == 'RECEIVED', 'missing receipt')
        else:
            require(fact['previousState'] == prior['state'] and
                    (fact['state'] != 'REJECTED' or fact['rejectionOrigin'] == 'CUSTODIAN'),
                    'invalid custody transition')
            prior = append(db, op, prior, fact['state'], fact=fact)
        db.execute('INSERT INTO custody_facts(operation_id,event) VALUES (%s,%s)', (op, Jsonb(fact)))
    if initial != prior['sequence']:
        db.execute('UPDATE operations SET updated_at=clock_timestamp() WHERE id=%s', (op,))
    set_delivery(db, op, 'CONFIRMED')
    schedule(db, op, recipient, None if prior['state'] in TERMINAL else interval)
    return prior['sequence'] - initial
