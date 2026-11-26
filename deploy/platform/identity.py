"""One-shot offline provisioning; no party mounts the other's private volume."""
from pathlib import Path
import json
import os
import shutil
from tempfile import TemporaryDirectory

from c1.policy import PARTICIPANTS
from c1.provision import provision
from spikes.tls.certificates import issue_ca, issue_leaf


def main():
    roles = ('manager', 'platform')
    if all((Path('/identities') / role / 'public.json').is_file() for role in roles):
        return  # Already provisioned. Never silently replace an existing identity.
    with TemporaryDirectory() as tmp:
        ca = Path(tmp)
        issue_ca(ca, 'lab-ca')
        rows = []
        for role in roles:
            target = Path('/identities') / role
            issue_leaf(ca, role, 'lab-ca', 'client' if role == 'manager' else 'server',
                       role + '.cafi.test', role)
            provision(target / 'message', PARTICIPANTS[role], PARTICIPANTS[role] + '-0')
            rows += json.loads((target / 'message/registry.json').read_bytes())
            for name in ('lab-ca.pem', role + '.pem', role + '.key'):
                shutil.copy(ca / name, target / name)
        for role in roles:
            target = Path('/identities') / role
            (target / 'public.json').write_text(json.dumps(rows))
            for path in [target, *target.rglob('*')]:
                os.chown(path, 999, 999)


if __name__ == '__main__':
    main()
