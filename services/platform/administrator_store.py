"""Durable SOAP work on the platform database, without financial state writes."""
from datetime import datetime
from typing import NamedTuple
from uuid import UUID

from psycopg.types.json import Jsonb

from c1.runtime import require
from .store import state_fields

REGISTER, GET = 'REGISTER_OPERATION', 'QUERY_ADMIN_RECORD'
KEY = "operation_id=%s AND recipient=%s AND message_type='REGISTER_OPERATION' AND instruction_version=1"


def business(manager, boleta, fact):
    return dict(managerId=manager, boleta=boleta, **{**state_fields(fact), 'sequence': str(fact['sequence'])})


def enqueue(db, operation, manager, boleta, fact):
    # Called only when applying a new verified terminal custody fact; neither
    # a local rejection nor a replay or old terminal projection calls this.
    db.execute("""INSERT INTO outbox(operation_id,recipient,message_type,instruction_version,payload,administrator_status)
                  VALUES (%s,%s,%s,1,%s,'PENDING')""",
               (operation, boleta['administratorId'], REGISTER, Jsonb(business(manager, boleta, fact))))


def owner(db, operation):
    return db.execute("""SELECT manager_id,boleta->>'portfolioId',boleta->>'administratorId'
                         FROM operations WHERE id=%s AND instruction_version=1""", (operation,)).fetchone()


class Job(NamedTuple):
    payload: dict
    status: str
    due: bool
    failures: int
    authority: UUID | None
    expires: datetime | None
    manager: str
    boleta: dict
    fact: dict | None

    @property
    def scope(self):
        return (self.manager, self.boleta['portfolioId'])

    def check(self, recipient):
        require(self.fact is not None and self.fact['origin'] == 'CUSTODIAN'
                and self.fact['state'] in ('SETTLED', 'SETTLEMENT_FAILED', 'REJECTED')
                and self.boleta['administratorId'] == recipient
                and self.payload == business(self.manager, self.boleta, self.fact), 'administrator outbox intent')


def reserve(db, operation, recipient):
    return db.execute('SELECT pg_try_advisory_lock(212,hashtext(%s))',
                      (f'{recipient}/{operation}',)).fetchone()[0]


def ready(db, recipient):
    return db.execute("""SELECT operation_id FROM outbox WHERE recipient=%s AND message_type=%s
        AND instruction_version=1 AND administrator_status IN ('PENDING','UNKNOWN')
        AND next_attempt_at<=now() ORDER BY operation_id""", (recipient, REGISTER)).fetchall()


def lock(db, operation, recipient):
    row = db.execute("""SELECT q.payload,q.administrator_status,q.next_attempt_at<=now(),q.recovery_failures,
        q.absence_id,CASE WHEN q.absence_expires_at>clock_timestamp() THEN q.absence_expires_at END,
        o.manager_id,o.boleta,(SELECT event FROM custody_facts WHERE operation_id=o.id ORDER BY sequence DESC LIMIT 1)
        FROM outbox q JOIN operations o ON o.id=q.operation_id
        WHERE q.operation_id=%s AND q.recipient=%s AND q.message_type=%s AND q.instruction_version=1
        FOR UPDATE OF q""", (operation, recipient, REGISTER)).fetchone()
    return Job(*row) if row else None


def unfinished(db, operation, recipient):
    return db.execute("""SELECT id,action,request_id FROM administrator_attempts
        WHERE operation_id=%s AND recipient=%s AND finished_at IS NULL""", (operation, recipient)).fetchone()


def begin(db, operation, recipient, action, proof):
    attempt, = db.execute("""INSERT INTO administrator_attempts(operation_id,recipient,action,authority_id)
        VALUES (%s,%s,%s,%s) RETURNING id""", (operation, recipient, action, proof)).fetchone()
    db.execute(f'UPDATE outbox SET absence_id=NULL,absence_expires_at=NULL WHERE {KEY}', (operation, recipient))
    return attempt


def prepared(db, operation, recipient, attempt, action, request, wire):
    saved = wire if action == REGISTER else None
    db.execute('UPDATE administrator_attempts SET request_id=%s,prepared_envelope=%s WHERE id=%s',
               (request, saved, attempt))
    if saved is not None:
        db.execute(f'UPDATE outbox SET prepared_envelope=%s,attempts=attempts+1 WHERE {KEY}',
                   (saved, operation, recipient))


def finish(db, attempt, outcome, *, code=None, response=None, delay=None):
    return db.execute("""UPDATE administrator_attempts SET finished_at=clock_timestamp(),
        outcome=%s,code=%s,response_id=%s,retry_delay_seconds=%s WHERE id=%s RETURNING finished_at""",
        (outcome, code, response, delay, attempt)).fetchone()[0]


def fail(db, operation, recipient, job, attempt, code, *, retry, delays, response=None):
    failures = job.failures + int(retry)
    delay = delays(failures) if retry else None
    status = 'UNKNOWN' if retry and failures < 5 else 'BLOCKED'
    finished = finish(db, attempt, 'RETRY' if status == 'UNKNOWN' else status,
                      code=code, response=response, delay=delay)
    db.execute(f"""UPDATE outbox SET administrator_status=%s,recovery_failures=%s,
        next_attempt_at=%s::timestamptz+%s*interval '1 second' WHERE {KEY}""",
        (status, failures, finished, delay or 0, operation, recipient))
    return status, delay


def allow_register(db, operation, recipient, proof_id, expires):
    db.execute(f"""UPDATE outbox SET absence_id=%s,absence_expires_at=%s,next_attempt_at=clock_timestamp()
                   WHERE {KEY}""", (proof_id, expires, operation, recipient))


def confirm(db, operation, recipient):
    db.execute(f"UPDATE outbox SET administrator_status='CONFIRMED',recovery_failures=0 WHERE {KEY}",
               (operation, recipient))
