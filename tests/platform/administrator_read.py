"""Exercise the platform's independent GetOperation callable on a real connection."""
import json
from pathlib import Path
import sys
from uuid import UUID

from services.platform.administrator import Client, get_operation
from services.platform.custody_worker import open_db


if __name__ == '__main__':
    mode, raw_op, *args = sys.argv[1:]
    op = str(UUID(raw_op))
    if mode == 'read':
        with open_db() as db:
            response = get_operation(db, Client(), op)
    elif mode == 'legacy-register':
        # Standalone S2-11 client identity and network, no platform database access.
        payload = json.loads(args[0])
        response = Client(Path('/identity')).exchange(op, (payload['managerId'], payload['boleta']['portfolioId']),
                                                       payload=payload, before_send=lambda *_: None)
    else:
        raise SystemExit('unknown mode')
    obs = response.observation
    print(json.dumps(dict(status=response.status, content=response.content, digest=response.digest.hex(),
                          link={k: obs[k] for k in ('protocol', 'group', 'ciphersuite', 'peerDnsSan', 'verifyCode')})))
