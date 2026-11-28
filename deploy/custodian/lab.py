"""Disposable S2-07 scenario; SQL witnesses run outside the client and listener."""
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from deploy.persistence import lab as db


def verify():
    for name, tag in [('platform', 's2-06'), ('custodian', 's2-07')]:
        subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', f'cafi-{name}:{tag}',
                        '-f', str(ROOT / f'deploy/{name}/Dockerfile'), str(ROOT)], check=True)
    scenario = 'custodian-' + uuid4().hex[:12]

    def compose(*args):
        subprocess.run(['docker', 'compose', '-p', db.project(scenario), '-f', str(db.HERE / 'compose.yaml'),
                        '-f', str(ROOT / 'deploy/custodian/compose.yaml'), *args], check=True)

    def client(*args):
        compose('run', '--rm', '-T', 'client', 'python', 'tests/custodian/exchanges.py', *args)

    def sql(statement, role='custodian'):
        return db.query(scenario, role, 'custodian', statement)

    def counts():
        return sql('SELECT (SELECT count(*) FROM inbox),(SELECT count(*) FROM instruction_events),'
                   '(SELECT count(*) FROM message_receipts)')

    try:
        db.up(scenario)
        compose('run', '--rm', '-T', 'identity')
        compose('up', '-d', '--wait', 'custodian')
        op = str(uuid4())
        client('receive', op)
        assert counts() == '1|1|7', counts()
        compose('restart', 'custodian')
        client('snapshot', op)
        assert counts() == '1|1|8', counts()
        sql('REVOKE INSERT ON message_receipts FROM custodian', 'postgres')
        client('rollback', str(uuid4()))
        assert counts() == '1|1|8', counts()
        sql('DELETE FROM portfolio_access', 'postgres')
        client('revoked', op)
        assert counts() == '1|1|8', counts()
        db.query(scenario, 'platform', 'custodian', 'SELECT 1', reject='permission denied for database')
        db.query(scenario, 'custodian', 'platform', 'SELECT 1', reject='permission denied for database')
        db.query(scenario, 'custodian', 'custodian', 'DELETE FROM inbox', reject='42501')
    finally:
        compose('--profile', 'tools', 'down', '--volumes')
    print('PASS 1 inbox, 1 event, 8 receipts; durable snapshot, rollback, revoked access, isolated roles; 0 skips')


if __name__ == '__main__':
    verify()
