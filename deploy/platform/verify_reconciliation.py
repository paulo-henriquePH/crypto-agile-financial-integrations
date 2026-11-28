"""S2-13 verification only: real services and persisted C1 source records."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
from uuid import UUID

from verify_administrator import FINANCIAL, GET, REGISTER, TERMINAL, TLS
from verify_custody import FILES, MON, ROOT, Scenario, db
from tests.reconciliation.lab_control import alter_registered_rate

EFFECTIVE = '2026-11-24'
RECONCILIATION = 'reconciliation-worker'


class Flow(Scenario):
    prefix, tag = 's213', 's2-13'
    files = (*FILES[:-1], 'deploy/administrator/compose.yaml', 'deploy/platform/administrator.compose.yaml',
             'deploy/platform/reconciliation.compose.yaml')

    def __init__(self, name):
        super().__init__(name)
        self.env['CAFI_ADMINISTRATOR_IMAGE'] = 'cafi-administrator:s2-13'

    def run(self, exercise):
        try:
            self.compose('up', '-d', '--wait', '--wait-timeout', '30', 'db')
            db.migrate(self.project)
            self.compose('exec', '-T', 'db', 'sh', '/opt/provision-runner.sh')
            self.runner('init', 'acceptance')
            for init in ('manager-identity-init', 'identity', 'administrator-identity-init'):
                self.compose('run', '--rm', '-T', init)
            self.compose('up', '-d', '--wait', '--wait-timeout', '30', 'platform', 'custodian', 'administrator')
            self.operation = str(UUID(self.manager('create', f'RECON-{self.name.upper()}')))
            exercise(self)
        finally:
            self.compose('--profile', 'tools', 'down', '--volumes')

    def api(self, status):
        return self.compose('run', '--rm', '-T', 'manager', 'python', 'tests/platform/reconciliation_manager.py',
                            self.operation, status, capture=True)

    def settle(self, *, with_intermediate=False):
        ack = self.worker()[-1]
        assert ack['result'] == 'RECEIVED' and ack['status'] == 202
        assert self.sql('SELECT count(*) FROM custody_snapshots') == '0'
        if with_intermediate:
            self.poll()
            assert self.sql("SELECT revision,snapshot->>'state' FROM custody_snapshots") == '1|RECEIVED'
            assert self.sql('SELECT count(*) FROM reconciliation_jobs') == '0'
            assert not self.reconcile()
            # A fresh query with identical facts does not create a revision.
            self.poll()
            assert self.sql('SELECT count(*) FROM custody_snapshots') == '1'
        self.runner('step', transitions=1)
        self.runner('step', transitions=1)
        self.runner('advance', EFFECTIVE, day=EFFECTIVE)
        self.runner('step', day=EFFECTIVE, transitions=1)
        start, end = self.poll()
        assert start['correlationId'] == end['correlationId'] and end['state'] == 'SETTLED'
        assert (start['protocol'], start['group'].upper(), start['ciphersuite']) == TLS
        assert self.sql('SELECT response_id FROM custody_snapshots WHERE revision=4') == end['messageId'] != ack['messageId']
        rev = json.loads(self.sql('SELECT snapshot FROM custody_snapshots WHERE revision=4'))
        remote = json.loads(self.sql("""SELECT i.payload || jsonb_build_object('events',
            (SELECT jsonb_agg(event ORDER BY sequence) FROM instruction_events WHERE operation_id=i.operation_id))
            FROM inbox i""", 'custodian'))
        expected_history = ['RECEIVED', 'ACCEPTED', 'PENDING_SETTLEMENT', 'SETTLED']
        assert rev == dict(**remote, state='SETTLED', sequence=4)
        assert [e['state'] for e in rev['events']] == expected_history
        assert (rev['boleta']['settlementDate'], rev['events'][-1]['occurredAt']) == (MON, f'{EFFECTIVE}T00:00:00Z')
        receipt = json.loads(self.sql(f"SELECT result FROM message_receipts WHERE message_id='{end['messageId']}'"))
        assert receipt == dict(kind='CUSTODY_RESPONSE', status=200, messageType='QUERY_INSTRUCTION_RESULT',
                               operationId=self.operation, requestMessageId=end['correlationId'])
        custody_wire = self.wire('custodian')[-1]
        assert (custody_wire['messageId'], custody_wire['correlationId'], custody_wire['group'].upper(),
                custody_wire['signatureProfile']) == (end['messageId'], end['correlationId'], 'X25519', 'ECDSA')
        return rev

    def reconcile(self, error=False):
        return self.once('--absence-interval', '.1', '--retry-base', '.1', '--exchange-timeout', '3',
                         expected=(int(error),), service=RECONCILIATION)

    def publish(self):
        sent, ack = self.once(expected=(0,), service='administrator-worker')
        assert (sent['action'], sent['result'], ack['action'], ack['result']) == (
            REGISTER, 'SENDING', REGISTER, 'CONFIRMED')
        assert self.sql("SELECT administrator_status FROM outbox WHERE message_type='REGISTER_OPERATION'") == 'CONFIRMED'
        return ack

    def wire(self, service, *expected):
        all_rows = map(json.loads, self.compose('logs', '--no-log-prefix', service, capture=True).splitlines())
        rows = [e for e in all_rows if e.get('operationId') == self.operation]
        if service == 'administrator':
            assert [(e['action'], e['status'], e.get('code')) for e in rows] == list(expected)
            assert len({e['correlationId'] for e in rows}) == len({e['messageId'] for e in rows}) == len(rows)
            for e in rows:
                assert (e['protocol'], e['group'].upper(), e['ciphersuite']) == TLS
                assert (e['peerDnsSan'], e['verifyCode'], e['keyId'], e['signatureProfile']) == (
                    'platform.cafi.test', 0, 'ADMINISTRADOR-DELTA-0', 'ECDSA')
        return rows

    def sources(self):
        return json.loads(self.sql("""SELECT coalesce(jsonb_agg(jsonb_build_object(
            'status',r.status,'version',r.instruction_version,'custodyRevision',r.custody_revision,
            'custody',c.snapshot,'manager',r.manager_snapshot,'administrator',r.administrator_snapshot,
            'administratorRevision',r.administrator_revision,'values',r.differences,
            'managerDigestMatches',r.manager_digest=o.digest,'receipt',m.result)
            ORDER BY r.checked_at),'[]') FROM reconciliation_results r JOIN message_receipts m
            ON m.message_id=r.administrator_response_id JOIN operations o ON o.id=r.operation_id
            JOIN custody_snapshots c ON (c.operation_id,c.instruction_version,c.revision)=
                (r.operation_id,r.instruction_version,r.custody_revision)"""))

    def financial(self):
        entries = self.sql('SELECT jsonb_agg(to_jsonb(e) ORDER BY kind) FROM settlement_entries e', 'custodian')
        assert self.sql(FINANCIAL, 'custodian') == '51950.00|107|ASSET_CREDIT,CASH_DEBIT'
        facts = self.sql('SELECT jsonb_agg(event ORDER BY sequence) FROM instruction_events', 'custodian')
        local = self.sql('SELECT updated_at,boleta,delivery_status,'
                         '(SELECT jsonb_agg(event ORDER BY sequence) FROM operation_events) FROM operations')
        assert [e['effective_date'] for e in json.loads(entries)] == [EFFECTIVE, EFFECTIVE]
        return local, facts, entries

    def checked(self, response, received):
        assert (response['protocol'], response['group'].upper(), response['ciphersuite']) == TLS
        assert (response['peerDnsSan'], response['verifyCode'], response['policyVersion'],
                response['keyId'], response['signatureProfile']) == (
                    'administrator.cafi.test', 0, 1, 'ADMINISTRADOR-DELTA-0', 'ECDSA')
        assert (response['messageId'], response['correlationId']) == (received['messageId'], received['correlationId'])


def incomplete_then_equal(s):
    early = json.loads(s.api('NOT_READY'))
    assert early['state'] == 'VALIDATED' and not s.reconcile() and not s.sources()
    custody = s.settle(with_intermediate=True)
    original = json.loads(s.api('NOT_READY'))
    finances = s.financial()
    assert [e['state'] for e in original['events']] == TERMINAL
    s.compose('stop', 'administrator')
    failure, = s.reconcile(error=True)
    assert failure['code'] == 'NETWORK_UNAVAILABLE' and not s.sources()
    assert s.sql("SELECT work_status,failures FROM reconciliation_jobs") == 'PENDING|1'
    assert json.loads(s.api('NOT_READY')) == original
    s.compose('up', '-d', '--wait', 'administrator')
    absent, = s.reconcile()
    assert (absent['result'], absent['code']) == ('NOT_READY', 'NOT_FOUND')
    missing, = s.sources()
    assert missing['administrator'] is None and missing['administratorRevision'] is None and not missing['values']
    assert missing['receipt']['code'] == 'NOT_FOUND' and missing['custody'] == custody
    ack = s.publish()
    assert json.loads(s.api('NOT_READY')) == original and s.sources() == [missing]
    with ThreadPoolExecutor(2) as pool:
        res = list(pool.map(lambda _: s.reconcile(), range(2)))
    checked, = [r for invocation in res for r in invocation]
    assert checked['result'] == 'MATCHED' and not s.reconcile()
    old, match = s.sources()
    assert old == missing and match['status'] == 'MATCHED' and match['values'] == []
    assert match['custody'] == custody and match['managerDigestMatches'] is True
    assert match['manager'] == dict(managerId=original['managerId'], boleta=original['boleta'])
    assert match['administrator'] == dict(**match['manager'], state='SETTLED', sequence='4')
    assert (match['version'], match['custodyRevision'], match['administratorRevision']) == (1, 4, '4')
    assert json.loads(s.api('MATCHED')) == dict(original, reconciliationStatus='MATCHED')
    actual = s.wire('administrator', (GET, 400, 'NOT_FOUND'), (REGISTER, 200, None), (GET, 200, None))
    s.checked(absent, actual[0])
    s.checked(checked, actual[2])
    assert ack['messageId'] == actual[1]['messageId'] != checked['messageId']
    assert s.financial() == finances
    s.evidence(TERMINAL, apiStatuses=['NOT_READY', 'NOT_READY', 'NOT_READY', 'MATCHED'],
               custodyRevisions=[1, 4], administratorRevision='4', plannedDate=MON, effectiveDate=EFFECTIVE,
               absenceReads=1, successfulIndependentReads=1, concurrentWorkers=2,
               sourcesPersisted=2, financialUnchanged=True, technicalFailure=failure['code'])


def divergent(s):
    custody = s.settle()
    original = json.loads(s.api('NOT_READY'))
    finances = s.financial()
    ack = s.publish()
    assert not s.sources() and json.loads(s.api('NOT_READY')) == original
    admin_before = json.loads(s.sql('SELECT snapshot FROM operation_snapshots', 'administrator'))
    assert admin_before['boleta'] == original['boleta']
    admin_digest = s.sql("SELECT encode(digest,'hex') FROM inbox", 'administrator')
    alter_registered_rate(s)
    s.sql("ALTER TABLE reconciliation_results ADD CONSTRAINT lab_deny_divergent CHECK (status<>'DIVERGENT') NOT VALID")
    rolled_back, = s.reconcile(error=True)
    assert rolled_back['code'] == '23514'
    assert not s.sources() and json.loads(s.api('NOT_READY')) == original
    assert s.sql(f"SELECT count(*) FROM message_receipts WHERE message_id='{rolled_back['messageId']}'") == '0'
    s.sql("ALTER TABLE reconciliation_results DROP CONSTRAINT lab_deny_divergent")
    checked, = s.reconcile()
    assert checked['result'] == 'DIVERGENT'
    divergence, = s.sources()
    reported = [dict(field='negotiatedRate', values=dict(
        manager='6.500000', custodian='6.500000', administrator='6.875001'))]
    assert divergence['values'] == reported and divergence['custody'] == custody
    assert divergence['manager'] == dict(managerId=original['managerId'], boleta=original['boleta'])
    assert divergence['administrator'] == dict(admin_before, boleta=dict(admin_before['boleta'], negotiatedRate='6.875001'))
    assert divergence['receipt']['messageType'] == 'QUERY_ADMIN_RECORD_RESULT'
    assert s.sql("SELECT encode(digest,'hex') FROM inbox", 'administrator') == admin_digest
    assert s.sql('SELECT count(*) FROM operation_snapshots', 'administrator') == '1'
    s.compose('restart', 'db')
    s.compose('up', '-d', '--wait', 'db')
    assert json.loads(s.api('DIVERGENT')) == dict(original, reconciliationStatus='DIVERGENT')
    assert s.sources() == [divergence] and not s.reconcile() and s.financial() == finances
    actual = s.wire('administrator', (REGISTER, 200, None), (GET, 200, None), (GET, 200, None))
    assert ack['messageId'] == actual[0]['messageId']
    s.checked(checked, actual[2])
    manager_wire = s.wire('platform')[-1]
    assert (manager_wire['group'].upper(), manager_wire['signatureProfile'], manager_wire['keyId'],
            manager_wire['status']) == ('X25519', 'ECDSA', 'PLATFORM-0', 200)
    s.sql('DELETE FROM portfolio_access')
    s.api('FORBIDDEN')
    assert s.sources() == [divergence] and s.financial() == finances
    s.evidence(TERMINAL, differences=reported, plannedDate=MON, effectiveDate=EFFECTIVE,
               independentGetResults=2, administratorSnapshots=1, resultCount=1,
               authorization='REST 403/FORBIDDEN; no payload leak', rollback=rolled_back['code'],
               durableAfterPostgresRestart=True, financialUnchanged=True)


def forbidden(s):
    s.settle()
    s.publish()
    initial = json.loads(s.api('NOT_READY'))
    finances = s.financial()
    s.sql('DELETE FROM portfolio_access', 'administrator')
    rejected, = s.reconcile(error=True)
    assert (rejected['code'], rejected['blocked']) == ('FORBIDDEN', True)
    assert not s.sources() and not s.reconcile() and s.financial() == finances
    assert json.loads(s.api('NOT_READY')) == initial and initial['state'] == 'SETTLED'
    assert s.sql("SELECT work_status,last_code FROM reconciliation_jobs") == 'BLOCKED|FORBIDDEN'
    _, fault = s.wire('administrator', (REGISTER, 200, None), (GET, 400, 'FORBIDDEN'))
    s.checked(rejected, fault)
    s.evidence(TERMINAL, signedFault='FORBIDDEN', reconciliationStatus='NOT_READY',
               administratorReadBlocked=True, resultCount=0, financialUnchanged=True)


EXERCISES = incomplete_then_equal, divergent, forbidden


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    names = {f.__name__: f for f in EXERCISES}
    parser.add_argument('scenarios', nargs='*', metavar='SCENARIO', help=', '.join(names))
    args = parser.parse_args()
    if set(args.scenarios) - names.keys() or not __debug__:
        parser.error('known scenario names and enabled assertions are required')
    for image in ('platform', 'custodian', 'administrator'):
        build = ['--build-arg', 'PLATFORM_IMAGE=cafi-platform:s2-13'] if image != 'platform' else []
        subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', f'cafi-{image}:s2-13',
                        '-f', str(ROOT / f'deploy/{image}/Dockerfile'), *build, str(ROOT)], check=True)
    selected = [f for name, f in names.items() if not args.scenarios or name in args.scenarios]
    for f in selected:
        Flow('missing' if f is incomplete_then_equal else f.__name__).run(f)
    print(f'PASS S2-13: {len(selected)} PostgreSQL/mTLS scenarios, 0 skips')


if __name__ == '__main__':
    main()
