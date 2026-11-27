"""S2-09: real manager, worker, C1 REST and independent PostgreSQL records."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
from time import monotonic, sleep
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests/contracts'))
from deploy.persistence import lab as db
from validate_events import replay

FILES = ('deploy/persistence/compose.yaml', 'deploy/platform/compose.yaml',
         'deploy/custodian/compose.yaml', 'deploy/custodian/settlement.compose.yaml',
         'deploy/platform/custody.compose.yaml', 'tests/platform/custody_defense.compose.yaml')
LOCAL = ['REGISTERED', 'VALIDATED', 'SENT', 'RECEIVED']
FRI, MON = '2026-11-20', '2026-11-23'


class Scenario:
    def __init__(self, name):
        self.name = name
        self.project = 's209-' + name + '-' + uuid4().hex[:8]
        self.env = {**os.environ, 'S2_09_FACTS': '', 'S2_09_REUSE_ID': '', 'S2_09_COLLISION_ID': ''}
        self.composed = ['docker', 'compose', '-p', db.project(self.project),
                         *(arg for path in FILES for arg in ('-f', str(ROOT / path)))]

    def compose(self, *args, rc=0, capture=False):
        out = subprocess.run([*self.composed, *args], check=False, capture_output=capture,
                             timeout=120, env=self.env, text=True, encoding='utf-8')
        expected = (rc,) if isinstance(rc, int) else rc
        assert out.returncode in expected, (args, out.returncode, out.stdout, out.stderr)
        return out.stdout

    def sql(self, sql, service='platform', role='postgres', reject=None):
        return db.query(self.project, role, service, sql, reject)

    def manager(self, *args):
        return self.compose('run', '--rm', '-T', 'manager', 'python', 'tests/platform/custody_flow.py',
                            *args, capture=True).strip()

    def history(self, *states):
        history = json.loads(self.manager('history', self.operation, *states))
        result = replay(history, 'CONFIRMED' if len(states) >= 4 else 'PENDING')
        assert (result['state'], result['sequence'], result['ignoredRepeatedEvents']) == (states[-1], len(states), 0)
        return history

    def runner(self, *args, day=FRI, transitions=0):
        out = json.loads(self.compose('run', '--rm', '-T', 'runner', *args, capture=True))
        assert (out['financialDay'], out['transitions']) == (day, transitions), out

    def worker(self, error=None, *, interval=1, race=False):
        lines = self.compose('run', '--rm', '-T', 'worker', '--once', '--poll-interval', str(interval),
                             rc=(0, 1) if race else (1 if error else 0), capture=True).splitlines()
        logs = [json.loads(line) for line in lines]
        if error:
            assert logs[-1]['result'] == 'FAILED' and logs[-1]['code'] == error, logs
        return logs

    def poll(self, error=None):
        self.wait(lambda: self.sql('SELECT poll_after<=now() FROM outbox') == 't')
        return self.worker(error=error)

    def wait(self, ready):
        deadline = monotonic() + 15
        while monotonic() < deadline:
            if ready():
                return
            sleep(.2)
        raise RuntimeError('worker or poll not ready in 15 s')

    def evidence(self, states, **observed):
        print(json.dumps(dict(scenario=self.name, operationId=self.operation, history=states,
                              **observed)), flush=True)

    def responses(self):
        lines = self.compose('logs', '--no-log-prefix', 'custodian', capture=True).splitlines()
        witnesses = [event for event in map(json.loads, lines) if event.get('event') == 'custody_wire_witness']
        return [{k: event[k] for k in ('messageId', 'digest', 'result')} for event in witnesses]

    def response_receipts(self):
        return json.loads(self.sql("""SELECT COALESCE(jsonb_agg(jsonb_build_object(
            'messageId',message_id,'digest',encode(digest,'hex'),'result',result) ORDER BY message_id),'[]')
            FROM message_receipts WHERE result->>'kind'='CUSTODY_RESPONSE'"""))

    def run(self, exercise):
        try:
            self.compose('up', '-d', '--wait', '--wait-timeout', '30', 'db')
            db.migrate(self.project)
            self.compose('exec', '-T', 'db', 'sh', '/opt/provision-runner.sh')
            self.runner('init', self.name if self.name == 'rejection' else 'acceptance')
            self.compose('run', '--rm', '-T', 'manager-identity-init')
            self.compose('run', '--rm', '-T', 'identity')
            self.compose('up', '-d', 'platform', 'custodian')
            self.operation = str(UUID(self.manager('create', 'FLOW-' + self.name.upper())))
            exercise(self)
        finally:
            self.compose('--profile', 'tools', 'down', '--volumes')


def observed_submission(s, attempt):
    assert attempt[0]['result'] == 'SENT' and attempt[1]['result'] == 'RECEIVED'
    msg = attempt[0]['correlationId']
    assert attempt[1]['correlationId'] == msg and attempt[1]['status'] == 202
    assert s.sql("""SELECT attempts,o.delivery_status,
          (convert_from(prepared_envelope,'UTF8')::jsonb#>>'{protected,messageId}'),
          (convert_from(prepared_envelope,'UTF8')::jsonb#>>'{protected,senderId}'),
          (convert_from(prepared_envelope,'UTF8')::jsonb#>>'{payload,managerId}')
          FROM outbox q JOIN operations o ON o.id=q.operation_id""") == f'1|CONFIRMED|{msg}|PLATFORM|GESTORA-ALFA'
    assert s.sql(f"""SELECT operation_id,sender,payload->>'managerId',
          (SELECT count(*) FROM message_receipts WHERE message_id='{msg}')
          FROM inbox""", 'custodian') == f'{s.operation}|PLATFORM|GESTORA-ALFA|1'
    return msg


def acceptance(s):
    # Failed SENT write rolls back the prepared wire and never reaches the remote inbox.
    s.sql("ALTER TABLE operation_events ADD CONSTRAINT deny_sent "
          "CHECK (event->>'state'<>'SENT') NOT VALID")
    s.worker(error='23514')
    assert s.sql('SELECT attempts,prepared_envelope IS NULL FROM outbox') == '0|t'
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '0'
    s.history(*LOCAL[:2])
    s.sql('ALTER TABLE operation_events DROP CONSTRAINT deny_sent')
    with ThreadPoolExecutor(2) as pool:
        a, b = pool.map(lambda _: s.worker(interval=5), range(2))
    assert not a or not b
    msg = observed_submission(s, a or b)
    ack_id = (a or b)[1]['messageId']
    assert s.response_receipts() == s.responses()
    assert len(s.response_receipts()) == 1 and s.response_receipts()[0]['messageId'] == ack_id
    s.manager('receipt-conflict', s.operation, ack_id)
    receipt_history = s.history(*LOCAL)
    results = [s.poll()]
    assert s.history(*LOCAL) == receipt_history
    s.runner('step', transitions=1)
    states = [*LOCAL, 'ACCEPTED']
    results.append(s.poll())
    accepted = s.history(*states)
    facts = s.sql('SELECT jsonb_agg(event ORDER BY sequence) FROM custody_facts')
    updated = s.sql('SELECT updated_at FROM operations')
    results.append(s.poll())  # Fresh query of the very same remote facts.
    assert s.history(*states) == accepted
    assert s.sql('SELECT jsonb_agg(event ORDER BY sequence) FROM custody_facts') == facts
    assert s.sql('SELECT updated_at FROM operations') == updated
    s.runner('step', transitions=1)
    states.append('PENDING_SETTLEMENT')
    results.append(s.poll())
    s.history(*states)
    s.runner('advance', MON, day=MON)
    s.runner('step', day=MON, transitions=1)
    states.append('SETTLED')
    results.append(s.poll())
    history = s.history(*states)
    assert not s.worker() and s.sql('SELECT poll_after IS NULL FROM outbox') == 't'
    assert [r[-1]['added'] for r in results] == [0, 1, 0, 1, 1]
    ids = [r[0]['correlationId'] for r in results]
    assert len(set(ids)) == len(ids) and msg not in ids
    assert all((r[0]['group'].upper(), r[0]['protocol'], r[0]['ciphersuite']) ==
               ('X25519', 'TLSv1.3', 'TLS_AES_256_GCM_SHA384') for r in results)
    assert all(projection['correlationId'] == request['correlationId'] != projection['messageId']
               for request, projection in results)
    assert s.sql('SELECT count(*) FROM message_receipts', 'custodian') == '6'
    receipts = s.response_receipts()
    assert len(receipts) == 6 and receipts == sorted(s.responses(), key=lambda row: row['messageId'])
    assert {r['messageId'] for r in receipts} == {ack_id, *(r[-1]['messageId'] for r in results)}
    remote = json.loads(s.sql('SELECT jsonb_agg(event ORDER BY sequence) FROM instruction_events', 'custodian'))
    assert json.loads(s.sql('SELECT jsonb_agg(event ORDER BY sequence) FROM custody_facts')) == remote
    assert [dict(e, sequence=e['sequence']-3) for e in history[4:]] == remote[1:]
    assert s.sql('SELECT (SELECT balance FROM settlement_cash),'
                 '(SELECT quantity FROM settlement_positions),(SELECT count(*) FROM settlement_entries)',
                 'custodian') == '51950.00|107|2'
    s.evidence(states, submitMessageId=msg, queryMessageIds=ids, tls=results[0][0]['protocol'],
               group=results[0][0]['group'], ciphersuite=results[0][0]['ciphersuite'],
               debitsAndCredits=2, duplicateAdded=results[2][-1]['added'],
               ackMessageId=ack_id, resultReceipts=len(receipts), matchedWireDigests=len(receipts),
               failedSentCommit='23514 without attempt or inbox')


def rejection(s):
    s.compose('up', '-d', 'worker')
    s.wait(lambda: s.sql('SELECT delivery_status FROM operations') == 'CONFIRMED')
    s.history(*LOCAL)
    s.runner('step', transitions=1)
    s.wait(lambda: s.sql("SELECT event->>'state' FROM operation_events ORDER BY sequence DESC LIMIT 1")
           == 'REJECTED')
    s.history(*LOCAL, 'REJECTED')
    assert s.sql('SELECT attempts,poll_after IS NULL FROM outbox') == '1|t'
    assert any(r['result']['status'] == 200 for r in s.response_receipts())
    assert s.sql('SELECT (SELECT balance FROM settlement_cash),'
                 '(SELECT quantity FROM settlement_positions),(SELECT count(*) FROM settlement_entries)',
                 'custodian') == '150000.00|7|0'
    s.evidence([*LOCAL, 'REJECTED'], reason='OPERATIONAL_REJECTION', rejectionOrigin='CUSTODIAN', entries=0)


def defensive(s):
    attempt = s.worker()
    observed_submission(s, attempt)
    s.runner('step', transitions=1)
    s.poll()
    states = [*LOCAL, 'ACCEPTED']
    accepted = s.history(*states)
    facts = s.sql('SELECT jsonb_agg(event ORDER BY sequence) FROM custody_facts')
    updated = s.sql('SELECT updated_at FROM operations')
    receipts = s.response_receipts()
    assert len(receipts) == 2
    s.runner('step', transitions=1)
    s.runner('advance', MON, day=MON)
    s.runner('step', day=MON, transitions=1)
    s.env['S2_09_FACTS'] = s.sql("SELECT payload||jsonb_build_object('events',"
                              "(SELECT jsonb_agg(event ORDER BY sequence) FROM instruction_events))"
                              " FROM inbox", 'custodian')
    s.env['S2_09_REUSE_ID'] = attempt[1]['messageId']
    # Negative-input harness only: use the test peer as sole server on this alias.
    s.compose('stop', 'custodian')
    s.compose('--profile', 'tools', 'up', '-d', '--wait', '--wait-timeout', '15', 'defensive-peer')
    checks = ['response correlation', 'custody history regression', 'custody history changed',
               'inconsistent custodian snapshot', 'invalid local transition', 'custody business mismatch',
               'response message ID reused', '23514']
    for check in checks:
        if check == '23514':
            s.sql("ALTER TABLE operation_events ADD CONSTRAINT deny_terminal "
                  "CHECK (event->>'state'<>'SETTLED') NOT VALID")
        # Re-arm explicitly only as test operator to present each independent negative.
        s.sql('UPDATE outbox SET poll_after=now()')
        s.poll(error=check)
        assert s.history(*states) == accepted
        assert s.sql('SELECT jsonb_agg(event ORDER BY sequence) FROM custody_facts') == facts
        assert s.sql('SELECT updated_at FROM operations') == updated
        assert s.response_receipts() == receipts
        assert s.sql('SELECT attempts,poll_after IS NULL FROM outbox') == '1|t'
    logs = s.compose('logs', '--no-log-prefix', 'defensive-peer', capture=True)
    assert logs.split() == ['wrong-correlation', 'regression', 'changed', 'gap', 'skip', 'business',
                            'reused-ID', 'rollback']
    s.evidence(states, rejected=checks, unchanged=True, resultReceipts=len(receipts))


def receipt_rollback(s):
    # The ID is inserted first; fail the financial write after a real correlated 202.
    s.sql("ALTER TABLE operation_events ADD CONSTRAINT deny_received "
          "CHECK (event->>'state'<>'RECEIVED') NOT VALID")
    s.worker(error='23514')
    s.history(*LOCAL[:3])
    witnesses = s.responses()
    assert len(witnesses) == 1 and witnesses[0]['result']['status'] == 202
    assert s.sql('SELECT attempts,prepared_envelope IS NOT NULL,poll_after IS NULL FROM outbox') == '1|t|t'
    assert s.sql("SELECT event->>'state' FROM instruction_events", 'custodian') == 'RECEIVED'
    assert s.response_receipts() == []
    s.evidence(LOCAL[:3], rolledBackMessageId=witnesses[0]['messageId'], resultReceipts=0)


def receipt_race(s):
    second = str(UUID(s.manager('create', 'FLOW-SECOND')))
    collision = str(uuid4())
    s.env['S2_09_COLLISION_ID'] = collision
    s.compose('up', '-d', 'custodian')
    with ThreadPoolExecutor(2) as pool:
        a, b = pool.map(lambda _: s.worker(interval=10, race=True), range(2))
    received, = [e for e in a+b if e['result'] == 'RECEIVED']
    denied, = [e for e in a+b if e['result'] == 'FAILED']
    winner, loser = received['operationId'], denied['operationId']
    assert {winner, loser} == {s.operation, second} and denied['code'] == 'response message ID reused'
    witnesses = s.responses()
    assert len(witnesses) == 2 and {r['messageId'] for r in witnesses} == {collision}
    assert len({r['digest'] for r in witnesses}) == 2
    assert s.response_receipts() == [r for r in witnesses if r['result']['operationId'] == winner]
    s.operation = winner
    s.history(*LOCAL)
    s.operation = loser
    s.history(*LOCAL[:3])
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '2'
    s.evidence(LOCAL[:3], confirmedOperationId=winner, collisionMessageId=collision, resultReceipts=1)


def verify():
    if not __debug__:
        raise SystemExit('verification requires assertions')
    for title, args in (
        ('platform', ()),
        ('custodian', ('--build-arg', 'PLATFORM_IMAGE=cafi-platform:s2-09')),
    ):
        subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', f'cafi-{title}:s2-09',
                        '-f', str(ROOT / f'deploy/{title}/Dockerfile'), *args, str(ROOT)], check=True)
    for exercise in (acceptance, rejection, defensive, receipt_rollback, receipt_race):
        Scenario(exercise.__name__.replace('_', '-')).run(exercise)
    print('PASS S2-09: 5 PostgreSQL/mTLS scenarios, 0 skips')


if __name__ == '__main__':
    verify()
