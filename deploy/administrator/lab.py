"""S2-11 verification in a fresh Compose project; SQL witnesses are not SOAP clients."""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from deploy.persistence import lab as db


def verify():
    for name in ('platform', 'administrator'):
        subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', f'cafi-{name}:s2-11',
                        '-f', str(ROOT / f'deploy/{name}/Dockerfile'), str(ROOT)], check=True)
    scenario = 'soap-' + uuid4().hex[:12]

    def compose(*args, capture=False):
        return subprocess.run(['docker', 'compose', '-p', db.project(scenario), '-f', str(db.HERE / 'compose.yaml'),
                               '-f', str(ROOT / 'deploy/administrator/compose.yaml'), *args],
                              check=True, text=True, encoding='utf-8', capture_output=capture).stdout

    def client(phase, target, *args):
        name = compose('run', '-d', '-T', 'administrator-client', 'python', 'tests/administrator/exchanges.py',
                       phase, target, *args, capture=True).strip()
        try:
            done = subprocess.check_output(['docker', 'wait', name], text=True, timeout=90).strip()
            logs = subprocess.check_output(['docker', 'logs', name], text=True, encoding='utf-8',
                                           stderr=subprocess.STDOUT).strip()
            if done != '0':
                raise RuntimeError(f'{phase}: client exit {done}\n{logs}')
            print(f'PASS {phase}: client exit 0', flush=True)
            return json.loads(logs) if logs else {}
        finally:
            subprocess.run(['docker', 'rm', '-f', name], check=True, stdout=subprocess.DEVNULL)

    def sql(statement, role='administrator', reject=None):
        return db.query(scenario, role, 'administrator', statement, reject=reject)

    def counts(*expected):
        state = sql('SELECT (SELECT count(*) FROM operation_snapshots),(SELECT count(*) FROM inbox),'
                    '(SELECT count(*) FROM message_receipts)')
        assert state == '|'.join(map(str, expected)), state

    try:
        db.up(scenario)
        compose('run', '--rm', '-T', 'administrator-identity-init')
        compose('up', '-d', '--wait', '--wait-timeout', '30', 'administrator')
        op = str(uuid4())
        counts(0, 0, 0)
        ids = client('exercise', op)
        counts(4, 4, 13)
        mid = UUID(ids['messageId'])
        assert sql(f"SELECT encode(digest,'hex') FROM message_receipts WHERE message_id='{mid}'") == ids['wireDigest']
        assert sql(f"""SELECT snapshot->>'state',snapshot->>'sequence',snapshot#>>'{{boleta,quantity}}',
                           snapshot#>>'{{boleta,unitPrice}}',snapshot#>>'{{boleta,grossAmount}}',
                           jsonb_typeof(snapshot->'sequence'),jsonb_typeof(snapshot#>'{{boleta,grossAmount}}')
                       FROM operation_snapshots WHERE operation_id='{op}'""") == (
            'SETTLED|9007199254740993|999999999|900000000.010000|899999999109999999.99|string|string')
        assert sql("SELECT string_agg(snapshot->>'state',',' ORDER BY snapshot->>'state') "
                   "FROM operation_snapshots") == 'REJECTED,REJECTED,SETTLED,SETTLEMENT_FAILED'
        neg = client('negatives', op)
        counts(4, 4, 13)
        client('expiry', op)
        counts(4, 4, 14)
        large_op = str(uuid4())
        sequence = client('sequence', large_op)
        counts(7, 7, 22)
        for witness in sequence['witnesses']:
            key = UUID(witness['operationId'])
            n = witness['digits']
            text = sql(f"SELECT snapshot->>'sequence' FROM operation_snapshots WHERE operation_id='{key}'")
            assert len(text) == n and sha256(text.encode()).hexdigest() == witness['sequenceSha256']
            assert sql(f"SELECT jsonb_typeof(snapshot->'sequence') FROM operation_snapshots "
                       f"WHERE operation_id='{key}'") == 'string'

        budget = client('envelope-budget', str(uuid4()))
        counts(9, 9, 31)
        for case in budget['cases']:
            key = UUID(case['operationId'])
            count = int(case['accepted'])
            assert sql(f"SELECT (SELECT count(*) FROM operation_snapshots WHERE operation_id='{key}'),"
                       f"(SELECT count(*) FROM inbox WHERE operation_id='{key}')") == f'{count}|{count}'
            for mid_str in case['receipts']:
                receipt_id = UUID(mid_str)
                row = sql(f"SELECT result->>0,coalesce(result#>>'{{1,code}}',''),"
                          f"coalesce(result#>>'{{1,message}}','') FROM message_receipts WHERE message_id='{receipt_id}'")
                if count:
                    assert row == '200||'
                elif mid_str == case['receipts'][-1]:
                    assert row == '400|NOT_FOUND|NOT_FOUND'
                else:
                    assert row == '400|INVALID_BUSINESS|SNAPSHOT_RESPONSE_TOO_LARGE'

        compose('restart', 'administrator')
        client('restart', op, large_op)
        counts(9, 9, 33)
        rollback_op = str(uuid4())
        sql('REVOKE INSERT ON message_receipts FROM administrator', 'postgres')
        client('rollback', rollback_op)
        assert sql(f"SELECT count(*) FROM operation_snapshots WHERE operation_id='{rollback_op}'") == '0'
        counts(9, 9, 33)
        sql('GRANT INSERT ON message_receipts TO administrator', 'postgres')
        sql('DELETE FROM portfolio_access', 'postgres')
        client('revoked', op)
        counts(9, 9, 33)

        sql('UPDATE operation_snapshots SET snapshot=snapshot', reject='42501')
        sql('DELETE FROM inbox', reject='42501')
        sql('DELETE FROM message_receipts', reject='42501')
        for role in ('platform', 'custodian'):
            db.query(scenario, role, 'administrator', 'SELECT 1', reject='permission denied for database')
            db.query(scenario, 'administrator', role, 'SELECT 1', reject='permission denied for database')

        events = [event for event in map(json.loads, compose('logs', '--no-log-prefix', 'administrator',
                   capture=True).splitlines()) if 'status' in event]
        assert Counter(e['status'] for e in events) == {200: 28, 400: 21, 500: 1}
        assert len({UUID(e['messageId']) for e in events}) == len(events)
        assert all((e['protocol'], e['group'].upper(), e['ciphersuite'], e['peerDnsSan'], e['verifyCode'],
                    e['signatureProfile'], e['keyId'], e['policyVersion']) ==
                   ('TLSv1.3', 'X25519', 'TLS_AES_256_GCM_SHA384', 'platform.cafi.test', 0, 'ECDSA',
                    'ADMINISTRADOR-DELTA-0', 1) for e in events)
        assert any(e['correlationId'] == str(mid) and e['operationId'] == op and e['status'] == 200 for e in events)
        print(json.dumps(dict(operationId=op, exactReplayMessageId=str(mid), rollbackOperationId=rollback_op,
                              signedResponses=len(events), statuses=dict(Counter(e['status'] for e in events)),
                              snapshots=9, inbox=9, receipts=33, negatives=neg, sequenceBoundary=sequence,
                              responseBudget=budget,
                              skips=0)), flush=True)
    finally:
        compose('--profile', 'tools', 'down', '--volumes')


if __name__ == '__main__':
    verify()
