"""Isolated signed negative inputs to the real REST response boundary and projector."""
from dataclasses import replace
import json
import os
from pathlib import Path
import socketserver
from uuid import uuid4

from c1.runtime import connect
from c1.transport import receive_request, send_response
from services.platform.messages import CREDENTIAL, SECRET, boundary, envelope

MODES = iter(('wrong-correlation', 'regression', 'changed', 'gap', 'skip', 'business', 'reused-ID', 'rollback'))


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with connect(CREDENTIAL, 'custodian', self.request, server=True, peer_dns='platform.cafi.test') as session:
            route, _, ctx = receive_request(session, incoming, lookup=lambda _: scope)
            assert ctx.action == 'QUERY_INSTRUCTION'
            mode = next(MODES)
            events = [dict(e) for e in snapshot['events']]
            business = {**snapshot['boleta']}
            if mode == 'wrong-correlation':
                ctx = replace(ctx, message=str(uuid4()))
            elif mode == 'regression':
                events = events[:1]
            elif mode == 'changed':
                events[0]['eventId'] = str(uuid4())
            elif mode == 'gap':
                del events[2]
                events[-1]['previousState'] = 'ACCEPTED'
            elif mode == 'skip':
                events = [*events[:2], {**events[-1], 'sequence': 3, 'previousState': 'ACCEPTED'}]
            elif mode == 'business':
                business['clientOrderId'] = 'DIFFERENT-ORDER'
            payload = dict(managerId=scope[0], boleta=business, events=events,
                           sequence=events[-1]['sequence'], state=events[-1]['state'])
            override = {'messageId': os.environ['S2_09_REUSE_ID']} if mode == 'reused-ID' else {}
            template = envelope(outgoing.policy, 'QUERY_INSTRUCTION_RESULT', payload, ctx.operation, ctx.message,
                                **override)
            send_response(session, outgoing, route, ctx, template, SECRET, 200)
            print(mode, flush=True)


if __name__ == '__main__':
    snapshot = json.loads(os.environ['S2_09_FACTS'])
    scope = snapshot['managerId'], snapshot['boleta']['portfolioId']
    incoming, outgoing = boundary(False, 'custodian'), boundary(True, 'custodian')
    with socketserver.TCPServer(('0.0.0.0', 8443), Handler) as server:
        Path('/tmp/ready').touch()
        server.serve_forever()
