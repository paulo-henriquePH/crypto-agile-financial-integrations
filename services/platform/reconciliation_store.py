"""Transactional source capture and reconciliation persistence on the platform DB."""
from typing import NamedTuple

from psycopg.types.json import Jsonb

from c1.runtime import require
from . import response_receipts
from .custody_store import TERMINAL
from .reconciliation import compare


KEY = 'operation_id=%s AND instruction_version=%s'


def capture(db, operation, version, snapshot, response_id, *, terminal):
    # A repeated query of the same already validated prefix has its own receipt,
    # but not a new business revision. The first accepted query pins that revision.
    revision = snapshot['sequence']
    db.execute("""INSERT INTO custody_snapshots(operation_id,instruction_version,revision,response_id,snapshot)
                  VALUES (%s,%s,%s,%s,%s) ON CONFLICT (operation_id,instruction_version,revision) DO NOTHING""",
               (operation, version, revision, response_id, Jsonb(snapshot)))
    if terminal:
        db.execute("""INSERT INTO reconciliation_jobs(operation_id,instruction_version,custody_revision)
                      VALUES (%s,%s,%s) ON CONFLICT (operation_id,instruction_version) DO NOTHING""",
                   (operation, version, revision))


class Job(NamedTuple):
    manager: str
    boleta: dict
    digest: bytes
    custody: dict
    revision: int
    failures: int

    @property
    def scope(self):
        return self.manager, self.boleta['portfolioId']


def ready(db, recipient):
    return db.execute("""SELECT j.operation_id,j.instruction_version FROM reconciliation_jobs j
        JOIN operations o ON o.id=j.operation_id AND o.instruction_version=j.instruction_version
        WHERE j.work_status='PENDING' AND j.next_attempt_at<=now() AND o.boleta->>'administratorId'=%s
        ORDER BY j.next_attempt_at,j.operation_id""", (recipient,)).fetchall()


def reserve(db, operation, version):
    # Each holder uses its own autocommit session; no DB transaction across SOAP I/O.
    return db.execute('SELECT pg_try_advisory_lock(213,hashtext(%s))',
                      (f'{operation}/{version}',)).fetchone()[0]


def due(db, operation, version, recipient):
    row = db.execute("""SELECT o.manager_id,o.boleta,o.digest,s.snapshot,j.custody_revision,j.failures
        FROM reconciliation_jobs j JOIN operations o
          ON o.id=j.operation_id AND o.instruction_version=j.instruction_version
        JOIN custody_snapshots s ON (s.operation_id,s.instruction_version,s.revision)=
                                     (j.operation_id,j.instruction_version,j.custody_revision)
        WHERE (j.operation_id,j.instruction_version)=(%s,%s)
          AND j.work_status='PENDING' AND j.next_attempt_at<=now() AND o.boleta->>'administratorId'=%s""",
        (operation, version, recipient)).fetchone()
    return Job(*row) if row else None


def defer(db, operation, version, failures, code, delay, *, blocked=False):
    db.execute(f"""UPDATE reconciliation_jobs SET failures=%s,last_code=%s,work_status=%s,
        next_attempt_at=clock_timestamp()+%s*interval '1 second'
        WHERE {KEY} AND work_status='PENDING'""",
        (failures, code, 'BLOCKED' if blocked else 'PENDING', delay, operation, version))


def record(db, operation, version, job, response):
    p, payload = response.content['protected'], response.content['payload']
    typ = p['messageType']
    require(p['operationId'] == operation and p['instructionVersion'] == version
            and typ in ('QUERY_ADMIN_RECORD_RESULT', 'ERROR'), 'reconciliation response context')
    if typ == 'QUERY_ADMIN_RECORD_RESULT':
        require(payload['state'] in TERMINAL, 'administrator result business')
    require(response_receipts.register(db, response, kind='ADMINISTRATOR_RESPONSE'), 'response message ID reused')
    if typ == 'ERROR' and payload['code'] != 'NOT_FOUND':
        return None
    manager = dict(managerId=job.manager, boleta=job.boleta)
    administrator = payload if typ == 'QUERY_ADMIN_RECORD_RESULT' else None
    status, differences = compare(manager, job.custody, administrator)
    db.execute("""INSERT INTO reconciliation_results(operation_id,instruction_version,custody_revision,
        administrator_response_id, manager_snapshot,manager_digest,administrator_snapshot,status,differences)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (operation, version, job.revision, p['messageId'], Jsonb(manager), job.digest,
         Jsonb(administrator) if administrator is not None else None, status, Jsonb(differences)))
    if status != 'NOT_READY':
        db.execute(f"""UPDATE reconciliation_jobs SET failures=0,last_code=NULL,work_status='DONE'
                       WHERE {KEY} AND work_status='PENDING'""", (operation, version))
        db.execute('UPDATE operations SET reconciliation_status=%s WHERE id=%s AND instruction_version=%s',
                   (status, operation, version))
    return status
