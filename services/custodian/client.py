"""Platform-side C1 exchanges. The caller supplies local ownership for queries."""
from contextlib import contextmanager
import socket

from c1.runtime import connect, require
from c1.security import Route
from c1.transport import receive_response, request_headers
from services.platform.messages import CREDENTIAL, SECRET, boundary, envelope


@contextmanager
def connection():
    dns = 'custodian.cafi.test'
    with socket.create_connection((dns, 8443), timeout=10) as sock, connect(
            CREDENTIAL, 'platform', sock, server=False, peer_dns=dns) as session:
        yield session


class Client:
    def __init__(self):
        self.out, self.back = boundary(False, 'custodian'), boundary(True, 'custodian')

    def prepare(self, session, operation, payload, lookup, **metadata):
        action = 'QUERY_INSTRUCTION' if payload is None else 'SUBMIT_INSTRUCTION'
        route = Route.expected(action, operation)
        wire, ctx = self.out.sign(envelope(self.out.policy, action, payload or {}, operation, **metadata),
                                  route, SECRET, session, lookup=lookup)
        return route, wire, ctx

    def send(self, session, route, wire, ctx):
        session.link.send(request_headers(route, session, wire), wire)
        status, content = receive_response(session, self.back, route, ctx)
        payload = content['payload']
        if status >= 400:
            codes = {'INVALID_SCHEMA': 400, 'FORBIDDEN': 403, 'NOT_FOUND': 404,
                     'IDEMPOTENCY_CONFLICT': 409, 'UNAVAILABLE': 503}
            require(codes.get(payload['code']) == status and payload['retryable'] == (status == 503),
                    'custodian error status')
        elif ctx.action == 'QUERY_INSTRUCTION':
            events = payload['events']
            require(events and events[0]['state'] == 'RECEIVED' and events[0].get('previousState') == 'SENT'
                    and all(e['sequence'] == i + 1 and e['operationId'] == ctx.operation
                            and e['instructionVersion'] == 1 and e['origin'] == 'CUSTODIAN'
                            and (i == 0 or e.get('previousState') == events[i-1]['state'])
                            for i, e in enumerate(events))
                    and (payload['sequence'], payload['state']) == (len(events), events[-1]['state']),
                    'inconsistent custodian snapshot')
        else:
            require(payload == dict(state='RECEIVED', sequence=1), 'invalid custodian receipt')
        return status, content

    def exchange(self, operation, payload, lookup):
        with connection() as session:
            return self.send(session, *self.prepare(session, operation, payload, lookup))
