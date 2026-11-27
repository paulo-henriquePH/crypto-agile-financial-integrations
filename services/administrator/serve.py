"""Independent SOAP listener; release business results only after commit."""
from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path
import socketserver
from uuid import uuid4

import h11
import psycopg

from c1.runtime import body, connect, require
from c1.security import Absent, Forbidden, InvalidRoute, Request, Route, fields, parse
from c1.transport import send_response
from services.platform.messages import CREDENTIAL, SECRET, boundary
from services.platform.store import stamp
from . import store
from .messages import fits_snapshot, response_template


def transact(incoming, outgoing, wire, route, session):
    with ExitStack() as stack:
        db, stored = None, None

        def lookup(ref):
            nonlocal db, stored
            db = stack.enter_context(psycopg.connect(host='db', user='administrator', dbname='administrator',
                password=Path('/credentials/administrator/password').read_text(), connect_timeout=3))
            stored = store.owner(db, ref)
            return stored

        try:
            signed, ctx = incoming.receive(wire, route, session, lookup=lookup)
            # No reparse and no XPath supplied by the sender. The only business
            # input is the Payload child of the exact verified SignedContent.
            payload = fields(signed.find(body.C + 'Payload')) if ctx.action == 'REGISTER_OPERATION' else None
        except Absent as exc:
            ctx, payload = exc.request, None
        except Forbidden as exc:
            return exc.request, store.fault(exc.request, 'FORBIDDEN')

        if not store.allowed(db, ctx, incoming.policy.scopes, stored, payload):
            ctx = replace(ctx, scope=None, error_only='FORBIDDEN')
            return ctx, store.fault(ctx, 'FORBIDDEN')
        outcome = store.apply(db, ctx, payload, wire,
                              fits=lambda snapshot: fits_snapshot(outgoing.policy, ctx.operation, snapshot))
        if ctx.error_only:
            # A reused messageId may conflict even on an authorized missing UUID.
            ctx = replace(ctx, error_only=outcome[1]['code'])
    return ctx, outcome


def unavailable_context(incoming, wire, route, session):
    """Recover only correlation on a DB failure, never pass this parse to business."""
    parsed, p, _ = parse(wire, xml=True)
    action, op = p['messageType'], p['operationId']
    require(action in incoming.policy.actions, 'unexpected action')
    route.check(action, op)
    incoming.authenticate(parsed, p, session)
    return Request(action, p['messageId'], op, p['senderId'], p['recipientId'], p['environment'],
                   None, error_only='UNAVAILABLE')


def handle(session, incoming, outgoing):
    head, wire = session.link.receive(h11.Request)
    try:
        require(not any(k == b'soapaction' for k, _ in head.headers), 'SOAP 1.1 action header')
        route = Route.from_request(head)
        ctx, (status, payload) = transact(incoming, outgoing, wire, route, session)
    except InvalidRoute as exc:
        ctx, route = exc.request, exc.protected_route
        status, payload = store.fault(ctx, 'INVALID_SCHEMA')
    except psycopg.Error:
        ctx = unavailable_context(incoming, wire, route, session)
        status, payload = store.fault(ctx, 'UNAVAILABLE', retryable=True)
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        auth = str(exc) in ('authenticated link', 'invalid signature', 'validity', 'direction',
                            'unauthorized key', 'inactive key', 'TLS/message key reuse')
        session.link.send(h11.Response(status_code=401 if auth else 400,
                                       headers=[('Content-Length', '0')]), b'')
        return

    kind, mid = ('ERROR' if status >= 400 else ctx.action + '_RESULT'), str(uuid4())
    template = response_template(outgoing.policy, kind, ctx.operation, payload, correlation=ctx.message,
                                 receiver_fault=status == 500, message_id=mid)
    send_response(session, outgoing, route, ctx, template, SECRET, status)
    obs = session.observation
    print(json.dumps(dict(service='administrator', at=stamp(), correlationId=ctx.message, messageId=mid,
        operationId=ctx.operation, instructionVersion=1, sender=ctx.sender, action=ctx.action, policyVersion=1,
        keyId=outgoing.policy.signing_key_id, group=obs['group'], protocol=obs['protocol'],
        ciphersuite=obs['ciphersuite'], peerDnsSan=obs['peerDnsSan'], verifyCode=obs['verifyCode'],
        signatureProfile='ECDSA', status=status, code=payload.get('code'))), flush=True)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        incoming, outgoing = self.server.boundaries
        with connect(CREDENTIAL, 'administrator', self.request, server=True,
                     peer_dns=incoming.policy.sender_dns) as session:
            handle(session, incoming, outgoing)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        print('{"service":"administrator","event":"exchange_failed"}', flush=True)


if __name__ == '__main__':
    with Server(('0.0.0.0', 8443), Handler) as server:
        server.boundaries = boundary(False, 'administrator'), boundary(True, 'administrator')
        server.serve_forever()
