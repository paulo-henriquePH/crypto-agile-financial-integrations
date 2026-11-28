"""S2-08: drive the private runner and verify signed REST plus PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from deploy.persistence import lab as db

HERE = Path(__file__).resolve().parent
COMPOSE_FILES = [arg for path in (db.HERE / 'compose.yaml', HERE / 'compose.yaml',
                                  HERE / 'settlement.compose.yaml') for arg in ('-f', str(path))]
FRI = '2026-11-20'
MON = '2026-11-23'
LATE_SUN = '2026-11-29'
LATE_MON = '2026-11-30'
RECEIVED = f'RECEIVED@{FRI}'
ACCEPTED = f'ACCEPTED@{FRI}'
PENDING = f'PENDING_SETTLEMENT@{FRI}'


class Scenario:
    def __init__(self, name):
        self.name = name
        self.scenario = 's208-' + name + '-' + uuid4().hex[:10]
        self.op = str(uuid4())

    def compose(self, *args, check=True, capture_output=False):
        return subprocess.run(['docker', 'compose', '-p', db.project(self.scenario), *COMPOSE_FILES,
                               *args], check=check, capture_output=capture_output, text=True, encoding='utf-8')

    def runner(self, command, *args, reject=None):
        result = self.compose('run', '--rm', '-T', 'runner', command, *args,
                              check=False, capture_output=True)
        if reject:
            assert result.returncode == 1 and reject in result.stderr, result.stderr
            return
        assert result.returncode == 0, result.stderr
        output = json.loads(result.stdout)
        return output['financialDay'], output['transitions']

    def client(self, command, *args):
        self.compose('run', '--rm', '-T', 'client', 'python', 'tests/custodian/settlement_exchanges.py',
                     command, self.op, *args)

    def sql(self, statement, role='postgres', reject=None, database='custodian'):
        return db.query(self.scenario, role, database, statement, reject)

    def snapshot(self, *history):
        self.client('snapshot', *history)
        assert self.sql("""SELECT string_agg(event->>'state',',' ORDER BY sequence)
                           FROM instruction_events""") == ','.join(s.split('@')[0] for s in history)
        assert self.sql('SELECT count(*) FROM inbox') == '1'

    def balances(self, cash, position, effective=None):
        assert self.sql('SELECT (SELECT balance FROM settlement_cash),'
                        '(SELECT quantity FROM settlement_positions)') == f'{cash}|{position}'
        entries = self.sql('SELECT operation_id,kind,portfolio_id,currency,asset_id,amount,quantity,effective_date '
                           'FROM settlement_entries ORDER BY kind')
        expected = (f'{self.op}|ASSET_CREDIT|FUNDO-ALFA||DEB-FICTICIA-01||100|{effective}\n'
                    f'{self.op}|CASH_DEBIT|FUNDO-ALFA|BRL||98050.00||{effective}') if effective else ''
        assert entries == expected, entries

    def history(self):
        return self.sql('SELECT jsonb_agg(event ORDER BY sequence) FROM instruction_events')

    def restart(self):
        self.compose('restart', 'db', 'custodian')
        self.compose('up', '-d', '--wait', 'custodian')

    def run(self, exercise):
        try:
            self.compose('up', '-d', '--wait', 'db')
            db.migrate(self.scenario)
            self.compose('exec', '-T', 'db', 'sh', '/opt/provision-runner.sh')
            assert self.runner('init', self.name) == (FRI, 0)
            self.compose('run', '--rm', '-T', 'identity')
            self.compose('up', '-d', '--wait', 'custodian')
            self.client('submit')
            self.snapshot(RECEIVED)
            exercise(self)
        finally:
            self.compose('--profile', 'tools', 'down', '--volumes')


def acceptance(s):
    s.client('deny-control')
    s.sql('UPDATE settlement_clock SET financial_day=CURRENT_DATE', 'custodian', '42501')
    s.sql('SELECT 1', 'platform', 'permission denied for database')
    s.sql('SELECT 1', 'custodian_runner', 'permission denied for database', database='platform')
    s.sql('UPDATE inbox SET result=result', 'custodian_runner', '42501')
    s.runner('init', 'rejection', reject='different fixture')
    s.balances('150000.00', 7)
    assert s.runner('step') == (FRI, 1)
    s.snapshot(RECEIVED, ACCEPTED)
    s.balances('150000.00', 7)
    assert s.runner('step') == (FRI, 1)
    s.snapshot(RECEIVED, ACCEPTED, PENDING)
    assert s.runner('step') == (FRI, 0)  # Friday is early for D+1 Monday.
    s.balances('150000.00', 7)
    assert s.runner('advance', LATE_SUN) == (LATE_SUN, 0)
    s.restart()
    assert s.runner('step') == (LATE_SUN, 0)  # Sunday is closed even after due date.
    s.snapshot(RECEIVED, ACCEPTED, PENDING)
    s.balances('150000.00', 7)
    assert s.runner('advance', LATE_MON) == (LATE_MON, 0)

    # Actual failing write after the cash debit, debit entry, and position update.
    s.sql("ALTER TABLE settlement_entries ADD CONSTRAINT verify_credit_fault "
          "CHECK (kind <> 'ASSET_CREDIT') NOT VALID")
    old_history = s.history()
    s.runner('step', reject='23514')
    s.snapshot(RECEIVED, ACCEPTED, PENDING)
    s.balances('150000.00', 7)
    assert s.history() == old_history
    s.sql('ALTER TABLE settlement_entries DROP CONSTRAINT verify_credit_fault')

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(s.runner, ['step', 'step'])) == [(LATE_MON, 0), (LATE_MON, 1)]
    terminal = f'SETTLED@{LATE_MON}'
    s.snapshot(RECEIVED, ACCEPTED, PENDING, terminal)
    s.balances('51950.00', 107, LATE_MON)
    s.sql("INSERT INTO settlement_entries SELECT * FROM settlement_entries WHERE kind='CASH_DEBIT'",
          'custodian_runner', '23505')
    history = s.history()
    s.restart()
    assert s.runner('init', 'acceptance') == (LATE_MON, 0)  # Not a reset.
    s.runner('advance', FRI, reject='cannot go backwards')
    assert s.runner('advance', LATE_MON) == (LATE_MON, 0)
    assert s.runner('step') == (LATE_MON, 0)
    s.client('submit')  # Reemission and exact transport replay preserve the first receipt.
    s.snapshot(RECEIVED, ACCEPTED, PENDING, terminal)
    s.balances('51950.00', 107, LATE_MON)
    assert s.history() == history
    print('PASS acceptance: isolated control, early/weekend holds, rollback, unique debit and credit, restart', flush=True)


def rejection(s):
    s.balances('150000.00', 7)
    assert s.runner('step') == (FRI, 1)
    terminal = f'REJECTED@{FRI}'
    s.snapshot(RECEIVED, terminal)
    assert s.runner('advance', MON) == (MON, 0)
    s.restart()
    assert s.runner('step') == (MON, 0)
    s.client('submit')
    s.snapshot(RECEIVED, terminal)
    s.balances('150000.00', 7)
    print('PASS rejection: operational reason, terminal history and no financial entries', flush=True)


def insufficient(s):
    s.balances('50000.00', 7)
    assert s.runner('step') == (FRI, 1)
    s.snapshot(RECEIVED, ACCEPTED)
    assert s.runner('step') == (FRI, 1)
    s.snapshot(RECEIVED, ACCEPTED, PENDING)
    assert s.runner('advance', MON) == (MON, 0)
    assert s.runner('step') == (MON, 1)
    terminal = f'SETTLEMENT_FAILED@{MON}'
    s.snapshot(RECEIVED, ACCEPTED, PENDING, terminal)
    s.balances('50000.00', 7)
    s.restart()
    assert s.runner('step') == (MON, 0)
    s.client('submit')
    s.snapshot(RECEIVED, ACCEPTED, PENDING, terminal)
    s.balances('50000.00', 7)
    print('PASS insufficient cash: full cash and position preserved; no financial entries', flush=True)


def verify():
    if not __debug__:
        raise SystemExit('verification requires assertions')
    for name, tag in [('platform', 's2-06'), ('custodian', 's2-08')]:
        subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', f'cafi-{name}:{tag}',
                        '-f', str(ROOT / f'deploy/{name}/Dockerfile'), str(ROOT)], check=True)
    for exercise in (acceptance, rejection, insufficient):
        Scenario(exercise.__name__).run(exercise)
    print('PASS S2-08: 3 PostgreSQL/mTLS scenarios, 0 skips')


if __name__ == '__main__':
    verify()
