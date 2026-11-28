"""Platform SOAP 1.2 client: business is extracted from the verified SignedContent."""
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
import socket
from time import monotonic

from c1.runtime import body, connect, http, require
from c1.security import Route, fields
from c1.soap import envelope
from c1.transport import receive_response_wire, request_headers
from . import administrator_store as store, response_receipts
from .custody import PreparationExpired
from .messages import boundary
from .store import intrinsic_rejection

CREDENTIAL = Path('/administrator-identity')
TRANSIENT = frozenset(('UNAVAILABLE', 'RATE_LIMITED'))


@dataclass(frozen=True)
class VerifiedResponse:
    status: int
    content: dict
    digest: bytes
    observation: dict


class Client:
    def __init__(self, directory=CREDENTIAL, *, connect_timeout=3, exchange_timeout=10):
        self.directory = directory
        self.secret = directory / 'message/message-private.pem'
        self.out = boundary(False, 'administrator', directory=directory)
        self.back = boundary(True, 'administrator', directory=directory)
        self.connect_timeout, self.exchange_timeout = connect_timeout, exchange_timeout

    def exchange(self, operation, scope, *, payload=None, before_send=None, proof_expires=None):
        action = store.GET if payload is None else store.REGISTER
        policy = self.out.policy
        require(scope in policy.scopes, 'portfolio permission')
        if action == store.REGISTER:
            require(before_send is not None and payload['boleta']['administratorId'] == policy.recipient
                    and (payload['managerId'], payload['boleta']['portfolioId']) == scope, 'administrator outbox intent')
        if proof_expires is not None and self.out.clock() >= proof_expires:
            raise PreparationExpired()
        route = Route.expected(action, operation)
        deadline = monotonic() + self.exchange_timeout
        with socket.create_connection((policy.recipient_dns, 8443),
                                      timeout=min(self.connect_timeout, self.exchange_timeout)) as sock, connect(
                self.directory, 'platform', sock, server=False,
                peer_dns=policy.recipient_dns, timeout=deadline - monotonic()) as session:
            issued = self.out.clock()
            template = envelope(policy, action, operation, payload or {}, issued=issued)
            wire, request = self.out.sign(template, route, self.secret, session, lookup=lambda _: scope)
            if before_send is not None:
                before_send(request, wire, session.observation)
            # Do not send after expiry, including time spent in the DB commit
            # or TLS write. The response retains the original exchange timeout.
            expires = issued + timedelta(seconds=120)
            before_clock = monotonic()
            remaining = ((min(expires, proof_expires) if proof_expires else expires) -
                         self.out.clock()).total_seconds()
            if remaining <= 0:
                raise PreparationExpired()
            try:
                session.link.send(request_headers(route, session, wire), wire, write_deadline=before_clock + remaining)
            except http.WriteDeadlineExpired as exc:
                raise PreparationExpired() from exc
            status, node, received = receive_response_wire(session, self.back, route, request)
            protected = fields(node.find(body.C + 'Protected'))
            result = fields(node.find(body.C + 'Payload'))
            if protected['messageType'] == 'ERROR':
                # The common boundary verifies signed NOT_FOUND only for a
                # query, non-retryable and with the two correlations checked.
                require(not result['retryable'] or result['code'] in TRANSIENT, 'administrator fault semantics')
            else:
                require(result['boleta']['administratorId'] == policy.recipient
                        and ('reason' not in result or bool(result['reason'].strip()))
                        and (result.get('rejectionOrigin') == 'LOCAL' or intrinsic_rejection(result['boleta']) is None),
                        'administrator result business')
                if payload is not None:
                    require(result == payload, 'administrator registration mismatch')
            return VerifiedResponse(status, dict(protected=protected, payload=result),
                                    sha256(received).digest(), session.observation)


def get_operation(db, client, operation):
    """Independent authenticated read for reconciliation; never a locally cached ACK.

    Use an autocommit platform connection. The caller receives either the verified
    snapshot or a verified Fault, and is responsible for interpreting differences.
    """
    require(db.autocommit, 'administrator query requires autocommit')
    operation = str(operation)
    owner = store.owner(db, operation)
    require(owner is not None and owner[2] == client.out.policy.recipient, 'administrator query scope')
    verified = client.exchange(operation, owner[:2])
    with db.transaction():
        require(response_receipts.register(db, verified, kind='ADMINISTRATOR_RESPONSE'), 'response message ID reused')
    return verified
