"""Run the real custodian with a test-only witness of the bytes sent by C1."""
from hashlib import sha256
import json
import os
from threading import Barrier

from c1.transport import send_response
from services.custodian import serve
from services.platform.messages import boundary

collision_id = os.environ.get('S2_09_COLLISION_ID')
gate = Barrier(2, timeout=8)


def witness(session, signer, route, request, template, secret, status):
    if collision_id and status == 202:
        value = json.loads(template)
        value['protected']['messageId'] = collision_id
        template = json.dumps(value).encode()
        gate.wait()  # Distinct real submit attempts race to reserve one response ID.
    wire = send_response(session, signer, route, request, template, secret, status)
    p = json.loads(wire)['protected']
    result = dict(kind='CUSTODY_RESPONSE', status=status, messageType=p['messageType'],
                  operationId=p['operationId'], requestMessageId=p['requestMessageId'])
    print(json.dumps(dict(event='custody_wire_witness', messageId=p['messageId'],
                          digest=sha256(wire).hexdigest(), result=result)), flush=True)


if __name__ == '__main__':
    serve.incoming, serve.outgoing = boundary(False, 'custodian'), boundary(True, 'custodian')
    serve.send_response = witness
    with serve.Server(('0.0.0.0', 8443), serve.Handler) as server:
        server.serve_forever()
