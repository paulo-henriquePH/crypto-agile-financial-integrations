"""Platform-side C1 exchanges. The caller supplies local ownership for queries."""
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import socket
from time import monotonic
from uuid import UUID

from c1.runtime import configured_client_spki, connect, require
from c1.security import Route, utc
from c1.transport import receive_response_wire, request_headers
from .messages import CREDENTIAL, boundary, envelope

DNS = 'custodian.cafi.test'


@dataclass(frozen=True)
class VerifiedResponse:
    status: int
    content: dict
    digest: bytes


@contextmanager
def connection(directory=CREDENTIAL, *, connect_timeout=3, exchange_timeout=10):
    deadline = monotonic() + exchange_timeout
    with socket.create_connection((DNS, 8443), timeout=min(connect_timeout, exchange_timeout)) as sock, connect(
            directory, 'platform', sock, server=False, peer_dns=DNS,
            timeout=deadline - monotonic()) as session:
        yield session


class Client:
    def __init__(self, directory=CREDENTIAL, *, connect_timeout=3, exchange_timeout=10):
        self.directory = directory
        self.secret = directory / 'message/message-private.pem'
        self.out = boundary(False, 'custodian', directory=directory)
        self.back = boundary(True, 'custodian', directory=directory)
        self.connect_timeout, self.exchange_timeout = connect_timeout, exchange_timeout

    def prepare_submission(self, operation, business):
        route = Route.expected('SUBMIT_INSTRUCTION', operation)
        local_spki = configured_client_spki(self.directory, 'platform')
        wire, ctx = self.out.prepare_rest(envelope(self.out.policy, 'SUBMIT_INSTRUCTION', business, operation),
                                          route, self.secret, local_spki)
        return route, wire, ctx, local_spki

    def connection(self):
        return connection(self.directory, connect_timeout=self.connect_timeout,
                          exchange_timeout=self.exchange_timeout)

    def submit(self, prepared):
        route, wire, ctx, local_spki = prepared
        with self.connection() as session:
            require(session.local_spki == local_spki and
                    session.observation['peerDnsSan'] == self.out.policy.recipient_dns,
                    'prepared envelope link binding')
            return self.send_verified(session, route, wire, ctx)

    def prepare(self, session, operation, payload, lookup, **metadata):
        action = 'QUERY_INSTRUCTION' if payload is None else 'SUBMIT_INSTRUCTION'
        route = Route.expected(action, operation)
        wire, ctx = self.out.sign(envelope(self.out.policy, action, payload or {}, operation, **metadata),
                                  route, self.secret, session, lookup=lookup)
        return route, wire, ctx

    def send(self, session, route, wire, ctx):
        response = self.send_verified(session, route, wire, ctx)
        return response.status, response.content

    def send_verified(self, session, route, wire, ctx):
        session.link.send(request_headers(route, session, wire), wire)
        status, content, received_wire = receive_response_wire(session, self.back, route, ctx)
        payload = content['payload']
        if status >= 400:
            codes = {'INVALID_SCHEMA': 400, 'FORBIDDEN': 403, 'NOT_FOUND': 404,
                     'IDEMPOTENCY_CONFLICT': 409, 'UNAVAILABLE': 503}
            require(codes.get(payload['code']) == status and payload['retryable'] == (status == 503),
                    'custodian error status')
        elif ctx.action == 'QUERY_INSTRUCTION':
            events = payload['events']
            require(events and events[0]['state'] == 'RECEIVED' and events[0].get('previousState') == 'SENT'
                    and all(type(e['sequence']) is int and e['sequence'] == i + 1
                            and e['operationId'] == ctx.operation
                            and type(e['instructionVersion']) is int and e['instructionVersion'] == 1
                            and str(UUID(e['eventId'])) == e['eventId']
                            and e['origin'] == 'CUSTODIAN'
                            and ('reason' not in e or bool(e['reason'].strip()))
                            and (i == 0 or e.get('previousState') == events[i-1]['state'])
                            for i, e in enumerate(events))
                    and type(payload['sequence']) is int and payload['sequence'] == len(events)
                    and all(payload.get(k) == events[-1].get(k)
                            for k in ('state', 'reason', 'rejectionOrigin')),
                    'inconsistent custodian snapshot')
            for e in events:
                utc(e['occurredAt'])
        else:
            require(payload == dict(state='RECEIVED', sequence=1) and type(payload['sequence']) is int,
                    'invalid custodian receipt')
        return VerifiedResponse(status, content, sha256(received_wire).digest())

    def exchange(self, operation, payload, lookup):
        with self.connection() as session:
            return self.send(session, *self.prepare(session, operation, payload, lookup))
