"""Platform overlay CLI. Reuse S2-04 lifecycle, role provisioning and migrations."""
import argparse
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from deploy.persistence import lab as db


def compose(scenario, *args, **kw):
    return subprocess.run(['docker', 'compose', '-p', db.project(scenario),
        '-f', str(db.HERE / 'compose.yaml'), '-f', str(ROOT / 'deploy/platform/compose.yaml'),
        *args], check=True, **kw)


def up(scenario):
    subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', 'cafi-platform:s2-06',
                    '-f', str(ROOT / 'deploy/platform/Dockerfile'), str(ROOT)], check=True)
    db.up(scenario)
    compose(scenario, 'run', '--rm', '-T', 'identity')
    compose(scenario, 'up', '-d', '--wait', 'platform')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('command', choices=['up', 'down', 'verify'])
    p.add_argument('scenario', nargs='?')
    args = p.parse_args()
    if args.command == 'verify':
        if args.scenario:
            p.error('verify always uses a fresh disposable scenario')
        from verify import verify
        scenario = 'platform-' + uuid4().hex[:12]
        try:
            up(scenario)
            verify(scenario, compose, db)
        finally:
            compose(scenario, '--profile', 'tools', 'down', '--volumes')
    elif not args.scenario:
        p.error('scenario required')
    elif args.command == 'down':
        compose(args.scenario, '--profile', 'tools', 'down', '--volumes')
    else:
        up(args.scenario)


if __name__ == '__main__':
    main()
