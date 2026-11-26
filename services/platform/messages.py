"""Lab C1 JSON envelope factory; no request-controlled policy choices."""
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from uuid import uuid4

from c1.policy import PARTICIPANTS, direction
from c1.security import Boundary, ECDSA, registry

CREDENTIAL = Path('/identity')
SECRET = CREDENTIAL / 'message/message-private.pem'


def boundary(response):
    kid = PARTICIPANTS['platform' if response else 'manager'] + '-0'
    keys = registry(json.loads((CREDENTIAL / 'public.json').read_bytes()))
    return Boundary(direction('platform', response=response, signing_key_id=kid, trusted_key_ids=[kid]), keys)


def envelope(policy, typ, payload, op=None, correlation=None, **overrides):
    now = datetime.now(UTC)
    signer = dict(algorithm=ECDSA, keyId=policy.signing_key_id)
    def stamp(t):
        return t.isoformat().replace('+00:00', 'Z')
    p = dict(schemaVersion='1.0', messageId=str(uuid4()), messageType=typ, senderId=policy.sender,
             recipientId=policy.recipient, environment=policy.environment, instructionVersion=1,
             issuedAt=stamp(now), expiresAt=stamp(now + timedelta(seconds=120)), policyVersion=1,
             signatureProfile='ECDSA', canonicalization='JCS', signers=[signer])
    if op:
        p['operationId'] = op
    if correlation:
        p['requestMessageId'] = correlation
    return json.dumps(dict(protected={**p, **overrides}, payload=payload,
                           signatures=[dict(**signer, value='AA==')])).encode()
