"""S2-12: platform SOAP publication/recovery, PostgreSQL and direct C1 mTLS."""
import argparse
import json
import os
from pathlib import Path
from shutil import unpack_archive
import subprocess
import sys
from tempfile import TemporaryDirectory
from uuid import UUID

from verify_custody import FILES, LOCAL, MON, ROOT, Scenario, db

BASE = '0729176f4b79f7cde9d432733015153b0f04d932'
REGISTER, GET = 'REGISTER_OPERATION', 'QUERY_ADMIN_RECORD'
TERMINAL = [*LOCAL, 'ACCEPTED', 'PENDING_SETTLEMENT', 'SETTLED']
REJECTED = [*LOCAL, 'REJECTED']
FAILED = [*TERMINAL[:-1], 'SETTLEMENT_FAILED']
FINANCIAL = ('SELECT (SELECT balance FROM settlement_cash),(SELECT quantity FROM settlement_positions),'
             "(SELECT coalesce(string_agg(kind,',' ORDER BY kind),'') FROM settlement_entries)")
TLS = ('TLSv1.3', 'X25519', 'TLS_AES_256_GCM_SHA384')


class Flow(Scenario):
    files = (*FILES[:-1], 'deploy/administrator/compose.yaml', 'deploy/platform/administrator.compose.yaml')
    prefix = 's212'
    tag = 's2-12'

    def __init__(self, name, instrument):
        super().__init__(name)
        self.env['CAFI_ADMINISTRATOR_IMAGE'] = 'cafi-administrator:s2-12-baseline' if name == 'legacy' else 'cafi-administrator:s2-12'
        self.env['CAFI_ADMINISTRATOR_MODULE'] = 'services.administrator.serve' if name == 'legacy' else 'tests.platform.administrator_peer'
        if instrument:
            self.composed += ['-f', str(ROOT / 'tests/platform/administrator_flow.compose.yaml')]

    @property
    def filter(self):
        return f"operation_id='{self.operation}' AND message_type='{REGISTER}'"

    def status(self):
        return self.sql(f'SELECT administrator_status,attempts,recovery_failures,absence_id IS NOT NULL '
                        f'FROM outbox WHERE {self.filter}')

    def intent(self):
        return json.loads(self.sql(f'SELECT payload FROM outbox WHERE {self.filter}'))

    def drive_terminal(self, scenario='acceptance', service='worker', *, finish=True):
        if service == 'worker':
            self.worker()
        else:
            assert self.once(expected=(0,), service=service)[-1]['result'] == 'RECEIVED'
        self.remote_terminal(scenario)
        if finish:
            if service == 'worker':
                self.poll()
            else:
                self.wait(lambda: self.sql("SELECT poll_after<=now() FROM outbox WHERE "
                                           "message_type='SUBMIT_INSTRUCTION'") == 't')
                assert self.once(expected=(0,), service=service)[-1]['result'] == 'PROJECTED'

    def remote_terminal(self, scenario='acceptance'):
        self.runner('step', transitions=1)
        if scenario != 'rejection':
            self.runner('step', transitions=1)
            self.runner('advance', MON, day=MON)
            self.runner('step', day=MON, transitions=1)

    def soap_work(self, error=None, *, timeout=3, retry_base=1):
        self.wait(lambda: self.sql(f"SELECT next_attempt_at<=now() FROM outbox WHERE {self.filter}") in ('', 't'))
        logs = self.once('--exchange-timeout', str(timeout), '--retry-base', str(retry_base),
                         expected=(int(bool(error)),), service='administrator-worker')
        if error:
            allowed = error if isinstance(error, tuple) else (error,)
            assert logs[-1]['result'] == 'FAILED' and logs[-1]['code'] in allowed, logs
        for row in logs:
            if row['result'] == 'SENDING':
                assert (row['protocol'], row['group'].upper(), row['ciphersuite']) == TLS
                assert (row['peerDnsSan'], row['verifyCode'], row['keyId'], row['policyVersion'],
                        row['signatureProfile']) == ('administrator.cafi.test', 0, 'PLATFORM-0', 1, 'ECDSA')
        return logs

    def mode(self, mode, custodian=False):
        self.compose('exec', '-T', 'custodian' if custodian else 'administrator', 'sh', '-c',
                     f'echo {mode} > /tmp/s2-{"10" if custodian else "12"}-mode')

    def read(self):
        response = json.loads(self.compose('run', '--rm', '-T', '--no-deps', '--entrypoint', 'python',
                                          'administrator-worker', 'tests/platform/administrator_read.py',
                                          'read', self.operation, capture=True))
        obs = response['link']
        assert (obs['protocol'], obs['group'].upper(), obs['ciphersuite']) == TLS
        assert (obs['peerDnsSan'], obs['verifyCode']) == ('administrator.cafi.test', 0)
        p = response['content']['protected']
        assert (p['senderId'], p['recipientId'], p['operationId'], p['instructionVersion'], p['policyVersion'],
                p['signatureProfile'], p['signers']) == ('ADMINISTRADOR-DELTA', 'PLATFORM', self.operation, 1, 1,
                    'ECDSA', [{'algorithm': 'ECDSA-P256-SHA256', 'keyId': 'ADMINISTRADOR-DELTA-0'}])
        mid, req = p['messageId'], p['requestMessageId']
        assert UUID(mid) != UUID(req) and self.sql(f"""SELECT encode(digest,'hex'),result->>'kind',
            result->>'requestMessageId' FROM message_receipts WHERE message_id='{UUID(mid)}'""") == (
            f"{response['digest']}|ADMINISTRATOR_RESPONSE|{req}")
        return p, response['content']['payload']

    def remote_count(self, records, receipts):
        assert self.sql('SELECT (SELECT count(*) FROM operation_snapshots),'
                        '(SELECT count(*) FROM inbox),(SELECT count(*) FROM message_receipts)',
                        'administrator') == f'{records}|{records}|{receipts}'

    def wire(self, event='s2-12-transaction'):
        lines = self.compose('logs', '--no-log-prefix', 'administrator', capture=True).splitlines()
        return [e for e in map(json.loads, lines) if e.get('event') == event]

    def transactions(self, *expected):
        rows = [r for r in self.wire() if r['operationId'] == self.operation]
        assert [r['action'] for r in rows] == list(expected), rows
        assert len({UUID(r['correlationId']) for r in rows}) == len(rows)
        for r in rows:
            assert (r['protocol'], r['group'].upper(), r['ciphersuite']) == TLS
            assert (r['peerDnsSan'], r['verifyCode']) == ('platform.cafi.test', 0)
        return rows

    def ledger(self):
        return json.loads(self.sql(f"""SELECT coalesce(jsonb_agg(jsonb_build_object(
            'action',action,'request',request_id,'response',response_id,'authority',authority_id,
            'outcome',outcome,'code',code,'delay',retry_delay_seconds) ORDER BY id),'[]')
            FROM administrator_attempts WHERE operation_id='{self.operation}'"""))

    def evidence(self, states, **observed):
        super().evidence(states, custodyFinancial=self.sql(FINANCIAL, 'custodian'),
                         soapLedger=self.ledger(), **observed)

    def run(self, exercise, *, migrate=db.migrate, fixture='acceptance'):
        try:
            self.compose('up', '-d', '--wait', '--wait-timeout', '30', 'db')
            migrate(self.project)
            self.compose('exec', '-T', 'db', 'sh', '/opt/provision-runner.sh')
            self.runner('init', fixture)
            for init in ('manager-identity-init', 'identity', 'administrator-identity-init'):
                self.compose('run', '--rm', '-T', init)
            self.compose('up', '-d', '--wait', '--wait-timeout', '30', 'platform', 'custodian', 'administrator')
            self.operation = str(UUID(self.manager('create', 'SOAP-' + self.name.upper())))
            exercise(self)
        finally:
            self.compose('--profile', 'tools', 'down', '--volumes')


def rollback_outage(s):
    s.drive_terminal(finish=False)
    base_history = s.history(*LOCAL)
    receipts = s.response_receipts()
    s.sql("ALTER TABLE outbox ADD CONSTRAINT deny_soap_intent CHECK (message_type<>'REGISTER_OPERATION') NOT VALID")
    s.poll(error='23514')
    assert s.history(*LOCAL) == base_history and s.response_receipts() == receipts and s.status() == ''
    assert s.sql('SELECT count(*) FROM custody_facts') == '0'
    s.remote_count(0, 0)
    s.sql('ALTER TABLE outbox DROP CONSTRAINT deny_soap_intent')
    s.compose('stop', 'administrator')
    s.wait(lambda: s.sql("SELECT next_attempt_at<=now() FROM outbox WHERE message_type='SUBMIT_INSTRUCTION'") == 't')
    s.worker()
    history = s.history(*TERMINAL)
    frozen = s.sql('SELECT updated_at,delivery_status,reconciliation_status FROM operations')
    assert s.status() == 'PENDING|0|0|f'
    assert s.intent()['sequence'] == '4' and history[-1]['sequence'] == 7
    s.soap_work('NETWORK_UNAVAILABLE')
    assert s.status() == 'UNKNOWN|0|1|f' and s.history(*TERMINAL) == history
    s.compose('up', '-d', '--wait', 'administrator')
    s.mode('outside')
    proof = s.soap_work()[-1]
    assert proof['result'] == 'NOT_FOUND' and s.status() == 'UNKNOWN|0|1|t'
    s.remote_count(0, 1)
    s.mode('pass')
    s.sql('REVOKE INSERT ON message_receipts FROM administrator', 'administrator')
    first_register = s.soap_work('UNAVAILABLE')
    assert first_register[0]['authorityId'] == proof['messageId']
    assert s.status() == 'UNKNOWN|1|2|f'
    s.remote_count(0, 1)
    s.sql('GRANT INSERT ON message_receipts TO administrator', 'administrator')
    next_proof = s.soap_work()[-1]
    assert next_proof['result'] == 'NOT_FOUND' and next_proof['messageId'] != proof['messageId']
    s.compose('restart', 'db')
    s.compose('up', '-d', '--wait', 'db')
    stored = s.soap_work()
    assert [r['result'] for r in stored] == ['SENDING', 'CONFIRMED']
    assert stored[0]['authorityId'] == next_proof['messageId']
    assert stored[0]['correlationId'] != first_register[0]['correlationId']
    assert s.status() == 'CONFIRMED|2|0|f' and s.history(*TERMINAL) == history
    assert s.sql("""SELECT count(*),count(DISTINCT request_id),count(DISTINCT (xpath(
        '//c:SignedContent/c:Payload',convert_from(prepared_envelope,'UTF8')::xml,
        ARRAY[ARRAY['c','urn:cafi:v1']]))::text) FROM administrator_attempts WHERE prepared_envelope IS NOT NULL""") == '2|2|1'
    s.remote_count(1, 3)
    assert s.read()[1] == s.intent()
    assert not s.soap_work()
    s.remote_count(1, 4)
    assert s.sql('SELECT updated_at,delivery_status,reconciliation_status FROM operations') == frozen
    receipts = json.loads(s.sql("""SELECT jsonb_object_agg(message_id,encode(digest,'hex'))
        FROM message_receipts WHERE result->>'kind'='ADMINISTRATOR_RESPONSE'"""))
    assert receipts == {w['messageId']: w['digest'] for w in s.wire('s2-12-wire')}
    assert s.sql(FINANCIAL, 'custodian') == '51950.00|107|ASSET_CREDIT,CASH_DEBIT'
    s.evidence(TERMINAL, sqlRollback='23514', historyUnchanged=True, reconciliationStatus='NOT_READY',
               remoteTransactions=s.transactions(GET, REGISTER, GET, REGISTER, GET), remoteSnapshots=1, remoteInbox=1,
               remoteReceipts=4, freshReissueSameBusiness=True, matchedWireDigests=len(receipts))


def lost_reply(s):
    s.mode('lose-submit', custodian=True)
    failed = s.once('--exchange-timeout', '2', expected=(1,))[-1]
    assert (failed['action'], failed['code']) == ('SUBMIT_INSTRUCTION', 'TIMEOUT')
    s.remote_terminal()
    s.mode('pass', custodian=True)
    s.wait(lambda: s.sql("SELECT next_attempt_at<=now() FROM outbox WHERE message_type='SUBMIT_INSTRUCTION'") == 't')
    s.worker()
    history = s.history(*TERMINAL)
    assert s.status() == 'PENDING|0|0|f'
    assert s.sql('SELECT count(*) FROM custody_facts') == '4'
    assert not s.ledger()
    s.mode('lose-register')
    s.compose('up', '-d', 'administrator-worker')
    s.wait(lambda: len(s.wire()) == 1)
    before = s.ledger()
    assert len(before) == 1 and before[0]['request'] == s.wire()[0]['correlationId'] and before[0]['outcome'] is None
    s.remote_count(1, 1)
    assert s.status() == 'PENDING|1|0|f'
    s.compose('kill', '-s', 'SIGKILL', 'administrator-worker')
    s.soap_work('INTERRUPTED')
    assert [e['outcome'] for e in s.ledger()] == ['RETRY']
    s.mode('lose-get')
    s.soap_work('TIMEOUT', timeout=2)
    assert s.status() == 'UNKNOWN|1|2|f'
    s.mode('pass')
    recovered = s.soap_work()[-1]
    assert (recovered['action'], recovered['result']) == (GET, 'CONFIRMED')
    assert s.status() == 'CONFIRMED|1|0|f'
    assert s.history(*TERMINAL) == history
    assert s.sql(FINANCIAL, 'custodian') == '51950.00|107|ASSET_CREDIT,CASH_DEBIT'
    s.remote_count(1, 3)
    a, b = s.read(), s.read()
    assert a[1] == b[1] == s.intent()
    assert a[0]['requestMessageId'] != b[0]['requestMessageId']
    assert a[0]['messageId'] != b[0]['messageId'] != recovered['messageId']
    s.remote_count(1, 5)
    assert s.sql("SELECT count(*) FROM message_receipts WHERE result->>'kind'='ADMINISTRATOR_RESPONSE'") == '3'
    assert not s.soap_work()
    s.evidence(TERMINAL, remoteTransactions=s.transactions(REGISTER, GET, GET, GET, GET),
               lostAfterCommit=True, workerKilled=True, custodyRecovered=True, independentReads=2,
               remoteSnapshots=1, remoteInbox=1, remoteReceipts=5, reconciliationStatus='NOT_READY')


def rejection(s):
    local = s.compose('run', '--rm', '-T', 'manager', 'python', '-c',
        "from tests.platform.exchanges import B, exchange; "
        "status, op, snapshot, _ = exchange(dict(B, clientOrderId='SOAP-LOCAL-REJECTION',grossAmount='98050.01')); "
        "assert (status,snapshot['state'],snapshot['rejectionOrigin']) == (201,'REJECTED','LOCAL'); print(op)",
        capture=True).strip()
    assert s.sql(f"SELECT count(*) FROM outbox WHERE operation_id='{UUID(local)}'") == '0'
    s.drive_terminal('rejection')
    assert s.status() == 'PENDING|0|0|f'
    history = s.history(*REJECTED)
    stored = s.soap_work()[-1]
    p, record = s.read()
    assert (record['state'], record['reason'], record['rejectionOrigin'], record['sequence']) == (
        'REJECTED', 'OPERATIONAL_REJECTION', 'CUSTODIAN', '2')
    assert stored['result'] == 'CONFIRMED' and s.status() == 'CONFIRMED|1|0|f'
    assert s.history(*REJECTED) == history and record == s.intent()
    assert s.sql(FINANCIAL, 'custodian') == '150000.00|7|'
    s.remote_count(1, 2)
    s.evidence(REJECTED, query=p['requestMessageId'], remoteSnapshots=1, remoteInbox=1, localRejectedWithoutIntent=True)


def insufficient(s):
    s.drive_terminal('insufficient')
    history = s.history(*FAILED)
    assert history[-1]['reason'] == 'INSUFFICIENT_CASH'
    assert s.soap_work()[-1]['result'] == 'CONFIRMED'
    _, record = s.read()
    assert record == s.intent() and record['state'] == 'SETTLEMENT_FAILED' and 'rejectionOrigin' not in record
    assert s.status() == 'CONFIRMED|1|0|f' and s.history(*FAILED) == history
    assert s.sql(FINANCIAL, 'custodian') == '50000.00|7|'
    s.remote_count(1, 2)
    s.evidence(FAILED, remoteSnapshots=1, remoteInbox=1)


def defensive(s):
    outcomes = []
    cases = (('business', 'administrator registration mismatch'),
             ('gross', 'administrator result business'),
             ('correlation', 'response correlation'), ('signature', 'invalid signature'),
             ('version', 'ValueError'), ('recovery-business', 'administrator recovery mismatch'),
             ('outside', 'FORBIDDEN'))
    for index, (mode, error) in enumerate(cases):
        if index:
            s.operation = str(UUID(s.manager('create', 'SOAP-NEG-' + mode.upper())))
        s.drive_terminal('rejection')
        history = s.history(*REJECTED)
        if mode == 'outside':
            s.compose('stop', 'administrator')
            s.soap_work('NETWORK_UNAVAILABLE')
            s.compose('up', '-d', '--wait', 'administrator')
            s.sql('DELETE FROM portfolio_access', 'administrator')
        if mode == 'recovery-business':
            s.mode('lose-register')
            s.soap_work('TIMEOUT', timeout=2)
            s.mode('business')
        else:
            s.mode(mode)
        s.soap_work(error)
        s.mode('pass')
        assert not s.soap_work() and s.history(*REJECTED) == history
        if mode == 'outside':
            assert s.status() == 'BLOCKED|0|1|f'
            attempted, = s.transactions(GET)
            assert attempted['status'] == 400
            assert s.ledger()[-1]['response'] is not None and s.ledger()[-1]['authority'] is None
        elif mode == 'recovery-business':
            assert s.status() == 'BLOCKED|1|1|f'
            s.transactions(REGISTER, GET)
            assert s.ledger()[-1]['response'] is None
        else:
            assert s.status() == 'BLOCKED|1|0|f'
            s.transactions(REGISTER)
            assert s.ledger()[-1]['response'] is None
        outcomes.append(dict(mode=mode, code=error, status=s.status()))
    s.remote_count(6, 7)
    assert s.sql("SELECT count(*) FROM message_receipts WHERE result->>'kind'='ADMINISTRATOR_RESPONSE'") == '1'
    assert s.sql(FINANCIAL, 'custodian') == '150000.00|7|'
    s.evidence(REJECTED, rejected=outcomes, remoteSnapshots=6, remoteInbox=6)


def exhausted(s):
    s.drive_terminal()
    history = s.history(*TERMINAL)
    s.sql('REVOKE INSERT ON message_receipts FROM administrator', 'administrator')
    for i in range(1, 6):
        row = s.soap_work('UNAVAILABLE', retry_base=.1)[-1]
        assert row['status'] == 500 and row['retryDelaySeconds'] == .1 * 2**(i-1)
        assert row['action'] == (REGISTER if i == 1 else GET)
        assert s.status() == f"{'UNKNOWN' if i < 5 else 'BLOCKED'}|1|{i}|f"
    s.sql('GRANT INSERT ON message_receipts TO administrator', 'administrator')
    assert not s.soap_work()
    assert s.history(*TERMINAL) == history and s.sql(FINANCIAL, 'custodian') == '51950.00|107|ASSET_CREDIT,CASH_DEBIT'
    s.remote_count(0, 0)
    p, fault = s.read()
    assert p['messageType'] == 'ERROR' and fault['code'] == 'NOT_FOUND'
    s.remote_count(0, 1)
    assert s.status() == 'BLOCKED|1|5|f'
    s.evidence(TERMINAL, failures=5, sixthAutomaticAttempt=False, remoteSnapshots=0, remoteInbox=0)


def legacy(s):
    assert s.sql("SELECT count(*) FROM schema_migration WHERE name LIKE '005_%'") == '0'
    s.drive_terminal(service='legacy-worker')
    history = s.history(*TERMINAL)
    b = json.loads(s.sql('SELECT boleta FROM operations'))
    # Existing external registration, legitimately signed through the separate
    # S2-11 endpoint. A different rate must remain observable by independent GET.
    b['negotiatedRate'] = '6.875000'
    snapshot = dict(managerId='GESTORA-ALFA', boleta=b, state='SETTLED', sequence='4')
    response = json.loads(s.compose('run', '--rm', '-T', 'administrator-client', 'python',
        'tests/platform/administrator_read.py', 'legacy-register', s.operation, json.dumps(snapshot), capture=True))
    assert response['status'] == 200
    s.remote_count(1, 1)
    db.migrate(s.project)
    assert s.sql("SELECT count(*) FROM schema_migration WHERE name LIKE '005_%'") == '1'
    assert s.status() == '' and not s.soap_work()
    p, record = s.read()
    assert record == snapshot and s.status() == '' and s.history(*TERMINAL) == history
    s.remote_count(1, 2)
    assert s.sql(FINANCIAL, 'custodian') == '51950.00|107|ASSET_CREDIT,CASH_DEBIT'
    s.evidence(TERMINAL, base=BASE, migrationFrom=4, independentQuery=p['requestMessageId'],
               differencesNotFiltered=True, legacyIntentBackfilled=False, remoteSnapshots=1, remoteInbox=1)


EXERCISES = (rollback_outage, lost_reply, rejection, insufficient, defensive, exhausted, legacy)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenarios', nargs='*', help='names: ' + ', '.join(f.__name__ for f in EXERCISES))
    args = parser.parse_args()
    selected = [f for f in EXERCISES if not args.scenarios or f.__name__ in args.scenarios]
    if set(args.scenarios) - {f.__name__ for f in EXERCISES} or not __debug__:
        parser.error('known scenario names and enabled assertions are required')
    for image in ('platform', 'custodian', 'administrator'):
        build = ['--build-arg', 'PLATFORM_IMAGE=cafi-platform:s2-12'] if image != 'platform' else []
        subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', f'cafi-{image}:s2-12',
                        '-f', str(ROOT / f'deploy/{image}/Dockerfile'), *build, str(ROOT)], check=True)
    windows_temp = Path(os.environ.get('LOCALAPPDATA', '')) / 'Temp/opencode'
    with TemporaryDirectory(prefix='s212-base-', dir=windows_temp if windows_temp.is_dir() else None) as area:
        reference = Path(area) / 'baseline'
        if legacy in selected:
            archive = Path(area) / 'baseline.tar'
            subprocess.run(['git', 'archive', f'--output={archive}', BASE], cwd=ROOT, check=True)
            unpack_archive(archive, reference)
            subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', 'cafi-platform:s2-12-baseline',
                            '-f', str(reference / 'deploy/platform/Dockerfile'), str(reference)], check=True)
            subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', 'cafi-administrator:s2-12-baseline',
                            '-f', str(reference / 'deploy/administrator/Dockerfile'), '--build-arg',
                            'PLATFORM_IMAGE=cafi-platform:s2-12-baseline', str(reference)], check=True)

        def migrate_legacy(project):
            subprocess.run([sys.executable, '-B', str(reference / 'deploy/persistence/lab.py'), 'migrate', project],
                           check=True)

        for f in selected:
            fixture = 'rejection' if f in (rejection, defensive) else 'insufficient' if f is insufficient else 'acceptance'
            Flow(f.__name__.replace('_', '-'), f in (rollback_outage, lost_reply, defensive, legacy)).run(
                f, migrate=migrate_legacy if f is legacy else db.migrate, fixture=fixture)
    print(f'PASS S2-12: {len(selected)} PostgreSQL/mTLS scenarios, 0 skips')


if __name__ == '__main__':
    main()
