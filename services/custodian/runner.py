"""Private S2-08 CLI. Invoked on the operator's Compose network, never by HTTP."""
import argparse
from datetime import date
import json
from pathlib import Path

import psycopg

from . import settlement

FIXTURES = Path(__file__).resolve().parents[2] / 'fixtures'
PASSWORD = Path('/credentials/custodian_runner/password')


def iso_day(text):
    try:
        day = date.fromisoformat(text)
        if text == day.isoformat():
            return day
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('expected an ISO date (YYYY-MM-DD)')


def main():
    fixture = json.loads((FIXTURES / 'custodian/settlement.json').read_bytes())
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init').add_argument('scenario', choices=fixture['scenarios'])
    commands.add_parser('advance').add_argument('day', type=iso_day)
    commands.add_parser('step')
    args = parser.parse_args()
    try:
        with psycopg.connect(host='db', user='custodian_runner', dbname='custodian',
                             password=PASSWORD.read_text(), connect_timeout=3) as db:
            if args.command == 'init':
                boleta = json.loads((FIXTURES / fixture['boletaTemplate']).read_bytes())
                day, changed = settlement.initialize(db, args.scenario, fixture, boleta), 0
            elif args.command == 'advance':
                day, changed = settlement.advance(db, args.day), 0
            else:
                day, changed = settlement.step(db)
    except (OSError, psycopg.Error) as exc:
        # Do not expose DSNs, constraint details, or payloads.
        parser.exit(1, f'runner storage error ({getattr(exc, "sqlstate", None) or "unavailable"})\n')
    except (ValueError, RuntimeError) as exc:
        parser.exit(1, f'{exc}\n')
    print(json.dumps(dict(financialDay=str(day), transitions=changed)))


if __name__ == '__main__':
    main()
