"""Direct mTLS listener for the manager integration."""
from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path
import socketserver
from uuid import UUID

import h11
import psycopg

from c1.runtime import connect, body
from c1.security import Absent, Forbidden, InvalidRoute, Request, Route
from c1.transport import send_response
from .messages import CREDENTIAL, SECRET, boundary, envelope
from . import store


def empty(session, status):
    session.link.send(h11.Response(status_code=status, headers=[('Content-Length', '0')]), b'')


def error_context(wire, route, session, code):
    """Recover only error correlation, never a grant or business content."""
    parsed = body.parse_json(wire)
    p = parsed.content['protected']
    action, op = p['messageType'], p.get('operationId')
    route.check(action, op)
    body.require(action in incoming.policy.actions and parsed.profile == 'ECDSA'
                 and str(UUID(p['messageId'])) == p['messageId']
                 and ((action == 'CREATE_OPERATION' and op is None) or
                      (action == 'QUERY_OPERATION' and str(UUID(op)) == op)), 'invalid context')
    incoming.authenticate(parsed, p, session)
    return Request(action, p['messageId'], op, p['senderId'], p['recipientId'], p['environment'],
                   None, error_only=code)


def handle(session):
    head, wire = session.link.receive(h11.Request)
    route = Route.from_request(head)
    try:
        ctx, outcome = transact(wire, route, session)
    except InvalidRoute as exc:
        # No scope resolver has run. Sign for the authenticated attempt, not
        # for the UUID supplied in the HTTP path.
        ctx, route = exc.request, exc.protected_route
        outcome = store.error(ctx, 400, 'INVALID_SCHEMA')
    except psycopg.Error:
        # Includes permission lookup, final receipt INSERT, and commit failures.
        ctx = error_context(wire, route, session, 'UNAVAILABLE')
        outcome = store.error(ctx, 503, 'UNAVAILABLE')
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        if str(exc) == 'envelope schema':
            try:
                ctx = error_context(wire, route, session, 'INVALID_SCHEMA')
            except (ValueError, KeyError, TypeError, AttributeError):
                empty(session, 400)
                return
            outcome = store.error(ctx, 400, 'INVALID_SCHEMA')
        else:
            auth = str(exc) in ('invalid signature', 'validity', 'direction', 'unauthorized key', 'inactive key')
            empty(session, 401 if auth else 400)
            return
    status, op, payload = outcome
    typ = 'ERROR' if status >= 400 else ctx.action + '_RESULT'
    template = envelope(outgoing.policy, typ, payload, op, ctx.message)
    send_response(session, outgoing, route, ctx, template, SECRET, status)
    protected = json.loads(template)['protected']
    print(json.dumps(dict(service='platform', at=store.stamp(), correlationId=ctx.message,
        messageId=protected['messageId'], operationId=op, instructionVersion=1, sender=ctx.sender,
        action=ctx.action, policyVersion=1, keyId=outgoing.policy.signing_key_id,
        group=session.observation['group'], signatureProfile='ECDSA', status=status, code=payload.get('code'))),
        flush=True)


def transact(wire, route, session):
    with ExitStack() as stack:
        db = None
        def lookup(ref):
            nonlocal db
            db = stack.enter_context(psycopg.connect(host='db', user='platform', dbname='platform',
                password=Path('/credentials/platform/password').read_text(), connect_timeout=3))
            return store.owner(db, ref)
        try:
            content, ctx = incoming.receive(wire, route, session, lookup=lookup)
            # Catalog access applies on every attempt, even after an earlier grant.
            if not db.execute("SELECT 1 FROM portfolio_access WHERE manager_id=%s AND portfolio_id=%s",
                              ctx.scope).fetchone():
                raise Forbidden('catalog access', replace(ctx, scope=None, error_only='FORBIDDEN'))
            outcome = store.apply(db, ctx, content['payload'], wire)
        except Forbidden as exc:
            ctx = exc.request
            outcome = store.error(ctx, 403, 'FORBIDDEN')
        except Absent as exc:
            ctx = exc.request
            outcome = store.absence(db, ctx, wire)
            if outcome[0] == 409:
                ctx = replace(ctx, error_only='IDEMPOTENCY_CONFLICT')
    return ctx, outcome


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with connect(CREDENTIAL, 'platform', self.request, server=True, peer_dns='manager.cafi.test') as session:
            handle(session)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    def handle_error(self, request, client_address):
        print('{"service":"platform","event":"exchange_failed"}', flush=True)


if __name__ == '__main__':
    incoming, outgoing = boundary(False), boundary(True)
    with Server(('0.0.0.0', 8443), Handler) as server:
        server.serve_forever()
