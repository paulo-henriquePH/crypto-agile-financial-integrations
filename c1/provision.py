"""Provision one synthetic message credential in a new external private directory."""
import argparse
import base64
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from spikes.tls.certificates import issue
from .runtime import ECDSA, ROOT, require


def provision(directory, sender, kid):
    require(all(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', s) for s in (sender, kid)), 'identifier')
    directory = directory.resolve()
    require(not directory.is_relative_to(ROOT), 'external secret mount required')
    directory.mkdir(mode=0o700)  # never overwrite/reuse an existing directory
    issue(directory, 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
          '-out', 'message-private.pem')
    with TemporaryDirectory(dir=directory) as tmp:
        der = Path(tmp) / 'public.der'
        issue(directory, 'pkey', '-in', 'message-private.pem', '-pubout', '-outform', 'DER', '-out', str(der))
        now = datetime.now(UTC).replace(microsecond=0)
        def stamp(t):
            return t.isoformat().replace('+00:00', 'Z')
        row = dict(senderId=sender, keyId=kid, algorithm=ECDSA, usage='MESSAGE', state='ACTIVE',
                   notBefore=stamp(now), notAfter=stamp(now + timedelta(days=1)),
                   public=base64.b64encode(der.read_bytes()).decode('ascii'))
        (directory / 'registry.json').write_text(json.dumps([row], indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('sender')
    parser.add_argument('keyId')
    args = parser.parse_args()
    provision(args.directory, args.sender, args.keyId)
