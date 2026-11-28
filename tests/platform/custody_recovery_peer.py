"""Wrap the real custodian only after its transaction, on the isolated Compose network."""
from base64 import b64decode, b64encode
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from time import sleep
from uuid import uuid4

import h11

from c1.transport import send_response
from services.custodian import serve, store
from services.platform.messages import boundary, envelope

MODE = Path('/tmp/s2-10-mode')


def reply(session, signer, route, request, template, secret, status):
    mode = MODE.read_text().strip() if MODE.exists() else 'pass'
    print(json.dumps(dict(event='s2-10-wire', mode=mode, action=request.action, operationId=request.operation,
                          correlationId=request.message, realStatus=status, group=session.observation['group'],
                          tls=session.observation['protocol'], ciphersuite=session.observation['ciphersuite'],
                          verifyCode=session.observation['verifyCode'])), flush=True)
    if mode == 'lose-submit' and request.action == 'SUBMIT_INSTRUCTION' and status == 202:
        sleep(12)   # mTLS established, real inbox transaction committed, no response bytes.
        return
    if request.action == 'QUERY_INSTRUCTION':
        if mode == 'lose-query':
            sleep(12)
            return
        if mode == 'gap' and status == 200:
            broken = json.loads(template)
            del broken['payload']['events'][2]
            template = json.dumps(broken).encode()
        if mode == 'prefix' and status == 200:
            older = json.loads(template)
            older['payload'].update(events=older['payload']['events'][:1], sequence=1, state='RECEIVED')
            template = json.dumps(older).encode()
        if mode == 'wrong-correlation' and status == 404:
            request = replace(request, message=str(uuid4()))
            template = envelope(signer.policy, 'ERROR', store.error(request, 404, 'NOT_FOUND')[2],
                                request.operation, request.message)
        if mode in ('short-absence', 'write-absence') and status == 404:
            value = json.loads(template)
            lifetime = 1 if mode == 'short-absence' else 6
            expiry = datetime.now(UTC) + timedelta(seconds=lifetime)
            value['protected']['expiresAt'] = expiry.isoformat().replace('+00:00', 'Z')
            template = json.dumps(value).encode()
        errors = {'schema': (400, 'INVALID_SCHEMA'), 'forbidden': (403, 'FORBIDDEN'),
                  'unavailable': (503, 'UNAVAILABLE'), 'rate-limit': (429, 'RATE_LIMITED'),
                  'contradictory-absence': (404, 'NOT_FOUND')}
        if mode in errors:
            status, code = errors[mode]
            request = replace(request, error_only=code)
            payload = store.error(request, status, code)[2]
            payload['retryable'] = status in (429, 503)
            template = envelope(signer.policy, 'ERROR', payload, request.operation, request.message)
        if mode in ('unsigned', 'bad-signature') and status == 404:
            wire = b'{}'
            if mode == 'bad-signature':
                signed, _ = signer.sign(template, route, secret, session, request=request)
                value = json.loads(signed)
                sig = value['signatures'][0]
                exact = b64decode(sig['value'])
                sig['value'] = b64encode(exact[:-1] + bytes([exact[-1] ^ 1])).decode()
                wire = json.dumps(value).encode()
            session.link.send(h11.Response(status_code=status, headers=[
                ('Content-Type', route.media), ('Content-Length', str(len(wire)))]), wire)
            return
    send_response(session, signer, route, request, template, secret, status)


if __name__ == '__main__':
    serve.incoming, serve.outgoing = boundary(False, 'custodian'), boundary(True, 'custodian')
    serve.send_response = reply
    with serve.Server(('0.0.0.0', 8443), serve.Handler) as server:
        server.serve_forever()
