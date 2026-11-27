"""S2-10: durable S2-09 REST recovery against PostgreSQL and direct C1 mTLS."""
import argparse
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
from shutil import unpack_archive
import subprocess
import sys
from tempfile import TemporaryDirectory
from uuid import UUID

from verify_custody import FILES, LOCAL, MON, ROOT, Scenario, db

SUBMIT, QUERY = 'SUBMIT_INSTRUCTION', 'QUERY_INSTRUCTION'
TERMINAL = [*LOCAL, 'ACCEPTED', 'PENDING_SETTLEMENT', 'SETTLED']
BASE = 'a22db16f227a86e98e383a9db32ee627eba4f765'


class Recovery(Scenario):
    files = (*FILES[:-1], 'tests/platform/custody_recovery.compose.yaml')
    prefix = 's210'
    tag = 's2-10'

    def mode(self, mode):
        assert mode in ('pass', 'lose-submit', 'lose-query', 'gap', 'prefix', 'wrong-correlation', 'short-absence',
                        'write-absence',
                        'schema', 'forbidden', 'unavailable', 'rate-limit', 'unsigned', 'bad-signature',
                        'contradictory-absence')
        self.compose('exec', '-T', 'custodian', 'sh', '-c', f'echo {mode} > /tmp/s2-10-mode')

    def work(self, error=None):
        logs = self.once('--exchange-timeout', '2', expected=(int(error is not None),))
        if error:
            assert logs[-1]['result'] == 'FAILED' and logs[-1]['code'] in (
                error if isinstance(error, tuple) else (error,)), logs
        return logs

    def wait_due(self, *, timeout=15):
        self.wait(lambda: self.sql("SELECT next_attempt_at<=now() FROM outbox "
                                   f"WHERE operation_id='{self.operation}' AND message_type='{SUBMIT}'") == 't', timeout=timeout)

    def retry(self, error=None):
        self.wait_due()
        return self.work(error)

    def restart_db(self):
        self.compose('restart', 'db')
        self.compose('up', '-d', '--wait', '--wait-timeout', '30', 'db')

    def wires(self):
        lines = self.compose('logs', '--no-log-prefix', 'custodian', capture=True).splitlines()
        events = [e for e in map(json.loads, lines) if e.get('event') == 's2-10-wire']
        assert all((e['tls'], e['group'].upper(), e['ciphersuite'], e['verifyCode']) ==
                   ('TLSv1.3', 'X25519', 'TLS_AES_256_GCM_SHA384', 0) for e in events)
        return [e for e in events if e['operationId'] == self.operation]

    def order(self, *actions):
        events = self.wires()
        assert [e['action'] for e in events] == list(actions), events
        assert len({e['correlationId'] for e in events}) == len(events)
        return events

    def ledger(self):
        return json.loads(self.sql(f"""SELECT coalesce(jsonb_agg(jsonb_build_object(
            'action',action,'request',request_id,'response',response_id,'outcome',outcome,
            'authority',authority_id,'code',code,'delay',retry_delay_seconds) ORDER BY id),'[]')
            FROM custody_attempts WHERE operation_id='{self.operation}'"""))

    def state(self):
        return self.sql(f"""SELECT q.attempts,o.delivery_status,q.recovery_failures
            FROM outbox q JOIN operations o ON o.id=q.operation_id
            WHERE o.id='{self.operation}' AND q.message_type='{SUBMIT}'""")

    def advance_to_settled(self):
        self.runner('step', transitions=1)
        self.runner('step', transitions=1)
        self.runner('advance', MON, day=MON)
        self.runner('step', day=MON, transitions=1)
        self.runner('step', day=MON)

    def settlement(self, done=False):
        assert self.sql("""SELECT (SELECT balance FROM settlement_cash),
            (SELECT quantity FROM settlement_positions),
            (SELECT coalesce(string_agg(kind,',' ORDER BY kind),'') FROM settlement_entries)""",
            'custodian') == ('51950.00|107|ASSET_CREDIT,CASH_DEBIT' if done else '150000.00|7|')

    def report(self, states, **observed):
        self.evidence(states, wire=self.wires(), ledger=self.ledger(), **observed)


def outbox(s):
    assert s.state() == '0|PENDING|0' and not s.ledger()
    s.history(*LOCAL[:2])
    s.restart_db()
    assert s.work()[-1]['result'] == 'RECEIVED'
    s.order(SUBMIT)
    s.history(*LOCAL)
    s.settlement()
    s.report(LOCAL, postgresRestart=True, submits=1)


def lost_reply(s):
    s.mode('lose-submit')
    s.work('TIMEOUT')
    assert s.state() == '1|UNKNOWN|1'
    before = s.history(*LOCAL[:3], delivery='UNKNOWN')
    assert not s.response_receipts()
    s.order(SUBMIT)
    s.mode('lose-query')
    s.retry('TIMEOUT')
    assert s.state() == '1|UNKNOWN|2' and s.history(*LOCAL[:3], delivery='UNKNOWN') == before
    s.order(SUBMIT, QUERY)
    s.restart_db()
    s.mode('pass')
    s.advance_to_settled()
    s.retry()
    s.history(*TERMINAL)
    assert s.state() == '1|CONFIRMED|0'
    assert len(s.response_receipts()) == 1 and s.response_receipts()[0]['result']['status'] == 200
    assert not s.work()
    s.order(SUBMIT, QUERY, QUERY)
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '1'
    assert s.sql('SELECT count(*) FROM custody_facts') == '4'
    s.settlement(done=True)
    s.report(TERMINAL, entries=2, submits=1, timeouts=2)


def killed(s):
    s.mode('lose-submit')
    s.compose('up', '-d', 'worker')
    s.wait(lambda: len(s.wires()) == 1)
    s.compose('kill', '-s', 'SIGKILL', 'worker')
    assert s.state() == '1|PENDING|0' and s.ledger()[0]['outcome'] is None
    assert s.sql("SELECT count(*) FROM inbox", 'custodian') == '1'
    s.work('INTERRUPTED')
    s.history(*LOCAL[:3], delivery='UNKNOWN')
    s.mode('pass')
    s.retry()
    s.history(*LOCAL)
    s.order(SUBMIT, QUERY)
    assert s.state() == '1|CONFIRMED|0'
    s.settlement()
    s.report(LOCAL, sigkillAfterRemoteCommit=True, submits=1)


def expired(s):
    s.compose('--profile', 'tools', 'up', '-d', 'stalled-worker')
    s.wait(lambda: 'stalled-before-socket' in s.compose('logs', 'stalled-worker', capture=True))
    s.compose('kill', '-s', 'SIGKILL', 'stalled-worker')
    s.order()
    assert s.state() == '1|PENDING|0'
    expired_id = s.ledger()[0]['request']
    s.work('INTERRUPTED')
    s.mode('short-absence')
    assert s.retry()[-1]['result'] == 'NOT_FOUND'
    short_id = s.ledger()[-1]['response']
    s.wait(lambda: s.sql("""SELECT absence_expires_at<now() AND
       (convert_from(prepared_envelope,'UTF8')::jsonb#>>'{protected,expiresAt}')::timestamptz
       + interval '5 seconds'<now() FROM outbox""") == 't')
    s.order(QUERY)
    s.mode('pass')
    assert s.work()[-1]['result'] == 'NOT_FOUND'
    current_id = s.ledger()[-1]['response']
    assert short_id != current_id
    s.restart_db()  # The verified proof, receipt and resubmission eligibility survive.
    s.mode('lose-submit')
    s.work('TIMEOUT')
    wires = s.order(QUERY, QUERY, SUBMIT)
    retry = s.ledger()[-1]
    assert retry['authority'] == current_id and retry['request'] == wires[-1]['correlationId'] != expired_id
    assert s.state() == '2|UNKNOWN|2' and s.sql('SELECT absence_id IS NULL FROM outbox') == 't'
    assert s.sql("""WITH envelopes AS (
        SELECT convert_from(prepared_envelope,'UTF8')::jsonb AS d FROM custody_attempts
        WHERE prepared_envelope IS NOT NULL
    ) SELECT count(*),count(DISTINCT d->'payload'),
             count(DISTINCT ((d->'protected')-'messageId'-'issuedAt'-'expiresAt')),
             count(DISTINCT d#>>'{protected,messageId}'),count(DISTINCT d#>>'{signatures,0,value}')
        FROM envelopes""") == '2|1|1|2|2'
    assert s.sql("""SELECT count(*),min(sender),min(payload->>'managerId')
         FROM inbox""", 'custodian') == '1|PLATFORM|GESTORA-ALFA'
    statuses = sorted(r['result']['status'] for r in s.response_receipts())
    assert statuses == [404, 404]
    s.history(*LOCAL[:3], delivery='UNKNOWN')
    s.mode('pass')
    s.advance_to_settled()
    s.retry()
    s.history(*TERMINAL)
    s.order(QUERY, QUERY, SUBMIT, QUERY)
    s.settlement(done=True)
    s.report(TERMINAL, expiredSubmitId=expired_id, expiredProofId=short_id, usedProofId=current_id, entries=2)


def gap(s, resolve):
    s.work()
    s.history(*LOCAL)
    s.advance_to_settled()
    s.mode('gap')
    assert s.poll('custody history gap')[-1]['gapThrough'] == 4
    assert s.state() == '1|CONFIRMED|1'
    assert s.sql('SELECT count(*) FROM custody_facts') == '0'
    assert len(s.response_receipts()) == 1
    s.history(*LOCAL)
    s.restart_db()
    assert s.sql('SELECT gap_through FROM outbox') == '4'
    s.mode('prefix')
    s.retry('custody history gap')
    assert s.sql('SELECT gap_through FROM outbox') == '4'
    assert s.state() == '1|CONFIRMED|2'
    if resolve:
        s.mode('pass')
        s.retry()
        s.history(*TERMINAL)
        assert s.sql('SELECT count(*) FROM custody_facts') == '4'
        assert s.state() == '1|CONFIRMED|0'
        assert s.sql(f"SELECT gap_through IS NULL FROM outbox WHERE message_type='{SUBMIT}'") == 't'
        assert len(s.response_receipts()) == 2
    else:
        s.mode('gap')
        for number in range(3, 6):
            s.retry('custody history gap')
            assert s.state() == f"1|{'CONFIRMED' if number < 5 else 'BLOCKED'}|{number}"
        s.history(*LOCAL, delivery='BLOCKED')
        assert s.sql('SELECT count(*) FROM custody_facts') == '0'
        assert s.sql('SELECT gap_through FROM outbox') == '4'
        assert len(s.response_receipts()) == 1
    s.order(SUBMIT, *([QUERY] * (3 if resolve else 5)))
    assert not s.work()
    s.settlement(done=True)
    s.report(TERMINAL if resolve else LOCAL, resolved=resolve, deferredThrough=4, entries=2)


def gap_closed(s):
    gap(s, True)


def gap_open(s):
    gap(s, False)


def unavailable(s):
    s.compose('stop', 'custodian')
    s.work('NETWORK_UNAVAILABLE')
    assert s.state() == '1|UNKNOWN|1' and s.ledger()[0]['delay'] == 1 and not s.response_receipts()
    s.compose('up', '-d', 'custodian')
    for n, mode, code in ((2, 'unavailable', 'UNAVAILABLE'), (3, 'rate-limit', 'RATE_LIMITED'),
                          (4, 'unavailable', 'UNAVAILABLE'), (5, 'lose-query', 'TIMEOUT')):
        s.mode(mode)
        s.retry(code)
        assert s.state() == f"1|{'UNKNOWN' if n < 5 else 'BLOCKED'}|{n}"
        s.history(*LOCAL[:3], delivery='UNKNOWN' if n < 5 else 'BLOCKED')
    ledger = s.ledger()
    assert [a['delay'] for a in ledger] == [1, 2, 4, 8, 16]
    assert [a['outcome'] for a in ledger] == ['RETRY'] * 4 + ['BLOCKED']
    assert s.sql("""WITH tries AS (
        SELECT *,lead(started_at) OVER (ORDER BY id) AS next_started FROM custody_attempts)
        SELECT bool_and(next_started >= finished_at+retry_delay_seconds*interval '1 second') FROM tries
        WHERE next_started IS NOT NULL""") == 't'
    s.order(*([QUERY] * 4))
    s.restart_db()
    s.mode('pass')
    s.wait_due(timeout=25)
    assert not s.work()
    s.order(*([QUERY] * 4))
    assert s.sql('SELECT attempts,prepared_envelope IS NOT NULL,absence_id IS NULL FROM outbox') == '1|t|t'
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '0'
    assert sorted(r['result']['status'] for r in s.response_receipts()) == [429, 503, 503]
    s.settlement()
    s.report(LOCAL[:3], entries=0, blockedAfter=5, observedBackoff=[1, 2, 4, 8, 16])


def disallowed(s):
    for i, (mode, code) in enumerate((('unsigned', ('ValueError', 'envelope schema')),
                                      ('wrong-correlation', 'response correlation'),
                                      ('bad-signature', 'invalid signature'),
                                      ('schema', 'INVALID_SCHEMA'), ('forbidden', 'FORBIDDEN'))):
        if i:
            s.operation = str(UUID(s.manager('create', 'BAD-' + mode)))
        s.compose('stop', 'custodian')
        s.work('NETWORK_UNAVAILABLE')
        s.history(*LOCAL[:3], delivery='UNKNOWN')
        s.compose('up', '-d', 'custodian')
        s.mode(mode)
        s.retry(code)
        assert s.state() == '1|BLOCKED|1'
        s.history(*LOCAL[:3], delivery='BLOCKED')
        s.mode('pass')
        assert not s.work()
        s.order(QUERY)
        assert s.ledger()[-1]['authority'] is None
        assert bool(s.ledger()[-1]['response']) == (mode in ('schema', 'forbidden'))
        s.report(LOCAL[:3], nonRetryableMode=mode, acceptedAbsence=False, entries=0)
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '0'
    assert s.sql('SELECT count(*) FROM outbox WHERE absence_id IS NOT NULL') == '0'
    s.settlement()


def known_receipt(s):
    s.work()
    confirmed = s.history(*LOCAL)
    s.mode('contradictory-absence')
    s.poll('unexpected custody absence')
    assert s.state() == '1|BLOCKED|0'
    assert s.history(*LOCAL, delivery='BLOCKED') == confirmed
    assert s.sql('SELECT absence_id IS NULL FROM outbox') == 't'
    assert sorted(r['result']['status'] for r in s.response_receipts()) == [202, 404]
    assert not s.work()
    s.order(SUBMIT, QUERY)
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '1'
    s.settlement()
    s.report(LOCAL, validButContradictoryAbsence=True, acceptedAbsence=False)


def write_expiry(s):
    s.compose('stop', 'custodian')
    s.work('NETWORK_UNAVAILABLE')
    s.compose('up', '-d', 'custodian')
    s.mode('write-absence')
    proof = s.retry()[-1]
    assert proof['result'] == 'NOT_FOUND'
    s.env['S2_10_PROOF_EXPIRES'] = s.sql('SELECT absence_expires_at FROM outbox')
    logs = s.once(expected=(1,), service='paused-writer')
    pause, = [e for e in logs if e.get('event') == 'before-first-tls-write']
    assert datetime.fromisoformat(pause['entered']) < datetime.fromisoformat(pause['expires'])
    assert datetime.fromisoformat(pause['resumed']) >= datetime.fromisoformat(pause['expires']) + timedelta(milliseconds=75)
    assert pause['tlsWrites'] == 0 and logs[-1]['code'] == 'PREPARATION_EXPIRED'
    assert s.state() == '2|UNKNOWN|2'
    s.history(*LOCAL[:3], delivery='UNKNOWN')
    assert s.ledger()[-1]['authority'] == proof['messageId']
    assert s.sql('SELECT absence_id IS NULL FROM outbox') == 't'
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '0'
    s.order(QUERY)
    s.mode('pass')
    fresh = s.retry()[-1]
    assert fresh['result'] == 'NOT_FOUND' and fresh['messageId'] != proof['messageId']
    assert s.work()[-1]['result'] == 'RECEIVED'
    assert s.ledger()[-1]['authority'] == fresh['messageId']
    s.order(QUERY, QUERY, SUBMIT)
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '1'
    s.history(*LOCAL)
    s.settlement()
    s.report(LOCAL, pause=pause, inboxBeforeFreshProof=0, inboxAfterFreshProof=1)


def migration(s):
    assert s.sql("SELECT count(*) FROM schema_migration WHERE name LIKE '004_%'") == '0'
    blocked = s.operation
    s.sql("DELETE FROM portfolio_access WHERE manager_id='GESTORA-ALFA' AND portfolio_id='FUNDO-ALFA'",
          'custodian')
    forbidden = s.once(expected=(1,), service='legacy-worker')[-1]
    assert (forbidden['status'], forbidden['code']) == (403, 'FORBIDDEN')
    s.history(*LOCAL[:3])
    assert [e['realStatus'] for e in s.order(SUBMIT)] == [403]
    s.sql("INSERT INTO portfolio_access VALUES ('GESTORA-ALFA','FUNDO-ALFA')", 'custodian')
    s.operation = inconclusive = str(UUID(s.manager('create', 'LEGACY-INCONCLUSIVE')))
    s.mode('lose-submit')
    assert s.once('--exchange-timeout', '2', expected=(1,), service='legacy-worker')[-1]['code'] == 'TimeoutError'
    s.history(*LOCAL[:3])
    assert [e['realStatus'] for e in s.order(SUBMIT)] == [202]
    s.mode('pass')
    s.operation = transient = str(UUID(s.manager('create', 'LEGACY-UNAVAILABLE')))
    s.sql(f"""ALTER TABLE inbox ADD CONSTRAINT s210_deny_submit
        CHECK (operation_id <> '{transient}'::uuid) NOT VALID""", 'custodian')
    unavailable_result = s.once(expected=(1,), service='legacy-worker')[-1]
    assert (unavailable_result['status'], unavailable_result['code']) == (503, 'UNAVAILABLE')
    s.history(*LOCAL[:3])
    assert [e['realStatus'] for e in s.order(SUBMIT)] == [503]
    s.sql('ALTER TABLE inbox DROP CONSTRAINT s210_deny_submit', 'custodian')
    assert {r['messageId'] for r in s.response_receipts()} == {forbidden['messageId'], unavailable_result['messageId']}
    assert s.sql('SELECT count(*) FROM outbox WHERE attempts=1') == '3'
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '1'

    db.migrate(s.project)
    assert s.sql("SELECT count(*) FROM schema_migration WHERE name='004_custody_recovery.sql'") == '1'
    assert s.sql("""SELECT count(*) FROM custody_attempts a JOIN outbox q USING (operation_id)
        WHERE a.prepared_envelope=q.prepared_envelope""") == '3'
    for s.operation, receipt, outcome, delivery in (
        (blocked, forbidden, 'BLOCKED', 'BLOCKED'), (transient, unavailable_result, 'LEGACY', 'UNKNOWN'),
        (inconclusive, None, 'LEGACY', 'UNKNOWN')
    ):
        entry, = s.ledger()
        assert entry['outcome'] == outcome and s.state() == f'1|{delivery}|0'
        assert entry['response'] == (receipt['messageId'] if receipt else None)
        assert entry['code'] == (receipt['code'] if receipt else None)
        if receipt:
            assert entry['request'] == receipt['correlationId']
        s.history(*LOCAL[:3], delivery=delivery)

    first = s.work()
    assert {e['operationId'] for e in first} == {inconclusive, transient}
    assert {e['result'] for e in first} == {'QUERY', 'PROJECTED', 'NOT_FOUND'}
    second = s.work()
    assert [(e['operationId'], e['result']) for e in second if e['action'] == SUBMIT] == [
        (transient, 'SENT'), (transient, 'RECEIVED')]
    for s.operation, actions, statuses in (
        (inconclusive, (SUBMIT, QUERY), [202, 200]),
        (transient, (SUBMIT, QUERY, SUBMIT), [503, 404, 202])
    ):
        # A normal follow-up poll for the confirmed operation may also be due.
        events = s.wires()
        assert [e['action'] for e in events[:len(actions)]] == list(actions)
        assert [e['realStatus'] for e in events[:len(actions)]] == statuses
        assert all(e['action'] == QUERY and e['realStatus'] == 200 for e in events[len(actions):])
        s.history(*LOCAL)
        s.report(LOCAL, legacyBase=BASE, entries=0)
    s.operation = blocked
    assert [e['realStatus'] for e in s.order(SUBMIT)] == [403]
    assert s.state() == '1|BLOCKED|0' and len(s.ledger()) == 1
    s.history(*LOCAL[:3], delivery='BLOCKED')
    assert s.sql('SELECT count(*) FROM inbox', 'custodian') == '2'
    s.settlement()
    s.report(LOCAL[:3], legacyBase=BASE, migrationFrom=3, migratedBlockedWithoutWire=True, entries=0)


EXERCISES = (outbox, lost_reply, killed, expired, gap_closed, gap_open, unavailable, disallowed, known_receipt,
             migration, write_expiry)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenarios', nargs='*', help='names: ' + ', '.join(f.__name__ for f in EXERCISES))
    args = parser.parse_args()
    selected = [f for f in EXERCISES if not args.scenarios or f.__name__ in args.scenarios]
    if set(args.scenarios) - {f.__name__ for f in EXERCISES} or not __debug__:
        parser.error('known scenario names and enabled assertions are required')
    for image, build_args in (('platform', []), ('custodian', ['--build-arg', 'PLATFORM_IMAGE=cafi-platform:s2-10'])):
        subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', f'cafi-{image}:s2-10',
                        '-f', str(ROOT / f'deploy/{image}/Dockerfile'), *build_args, str(ROOT)], check=True)
    windows_temp = Path(os.environ.get('LOCALAPPDATA', '')) / 'Temp/opencode'
    with TemporaryDirectory(prefix='s210-base-', dir=windows_temp if windows_temp.is_dir() else None) as area:
        reference = Path(area) / 'baseline'
        if migration in selected:
            archive = Path(area) / 'baseline.tar'
            subprocess.run(['git', 'archive', f'--output={archive}', BASE], cwd=ROOT, check=True)
            unpack_archive(archive, reference)
            subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', 'cafi-platform:s2-10-baseline',
                            '-f', str(reference / 'deploy/platform/Dockerfile'), str(reference)], check=True)

        def migrate_legacy(project):
            subprocess.run([sys.executable, '-B', str(reference / 'deploy/persistence/lab.py'), 'migrate', project],
                           check=True)

        for exercise in selected:
            Recovery(exercise.__name__.replace('_', '-')).run(
                exercise, migrate=migrate_legacy if exercise is migration else db.migrate)
    print(f'PASS S2-10: {len(selected)} PostgreSQL/mTLS scenarios, 0 skips')


if __name__ == '__main__':
    main()
