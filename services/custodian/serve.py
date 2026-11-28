"""One authenticated REST attempt; commit before emitting any business response."""
from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path
import socketserver
from uuid import UUID

import h11
import psycopg

from c1.runtime import body, connect
from c1.security import Absent, Forbidden, InvalidRoute, Request, Route
from c1.transport import send_response
from services.platform.messages import CREDENTIAL, SECRET, boundary, envelope
from services.platform.serve import empty
from . import store


def transact(wire, route, session):
    with ExitStack() as stack:
        db = None

        def lookup(ref):
            nonlocal db
            db = stack.enter_context(psycopg.connect(host='db', user='custodian', dbname='custodian',
                password=Path('/credentials/custodian/password').read_text(), connect_timeout=3))
            return store.owner(db, ref)

        try:
            content, ctx = incoming.receive(wire, route, session, lookup=lookup)
            if not db.execute("SELECT 1 FROM portfolio_access a JOIN portfolio p ON p.id=a.portfolio_id "
                              "WHERE a.manager_id=%s AND p.id=%s AND p.custodian_id=%s",
                              (*ctx.scope, ctx.recipient)).fetchone() or (
                    ctx.action == 'SUBMIT_INSTRUCTION' and content['payload']['boleta']['custodianId'] != ctx.recipient):
                raise Forbidden('catalog access', replace(ctx, scope=None, error_only='FORBIDDEN'))
            result = store.apply(db, ctx, content['payload'], wire)
        except Absent as exc:
            ctx = exc.request
            result = store.apply(db, ctx, None, wire)
            ctx = replace(ctx, error_only=result[2]['code'])
        except Forbidden as exc:
            ctx = exc.request
            result = store.error(ctx, 403, 'FORBIDDEN')
    return ctx, result


def error_context(wire, route, session, code):
    parsed = body.parse_json(wire)
    p = parsed.content['protected']
    body.require(parsed.profile == 'ECDSA' and p['messageType'] in incoming.policy.actions
                 and all(str(UUID(p[k])) == p[k] for k in ('operationId', 'messageId')), 'invalid context')
    route.check(p['messageType'], p['operationId'])
    incoming.authenticate(parsed, p, session)
    return Request(p['messageType'], p['messageId'], p['operationId'], p['senderId'], p['recipientId'],
                   p['environment'], None, error_only=code)


def handle(session):
    head, wire = session.link.receive(h11.Request)
    route = Route.from_request(head)
    try:
        ctx, outcome = transact(wire, route, session)
    except InvalidRoute as exc:
        ctx, route = exc.request, exc.protected_route
        outcome = store.error(ctx, 400, 'INVALID_SCHEMA')
    except psycopg.Error:
        ctx = error_context(wire, route, session, 'UNAVAILABLE')
        outcome = store.error(ctx, 503, 'UNAVAILABLE')
    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        if str(exc) != 'envelope schema':
            empty(session, 401 if str(exc) in ('invalid signature', 'validity', 'direction',
                                               'unauthorized key', 'inactive key') else 400)
            return
        try:
            ctx = error_context(wire, route, session, 'INVALID_SCHEMA')
        except (ValueError, KeyError, TypeError, AttributeError):
            empty(session, 400)
            return
        outcome = store.error(ctx, 400, 'INVALID_SCHEMA')
    status, op, payload = outcome
    template = envelope(outgoing.policy, 'ERROR' if status >= 400 else ctx.action + '_RESULT',
                        payload, op, ctx.message)
    send_response(session, outgoing, route, ctx, template, SECRET, status)
    print(json.dumps(dict(service='custodian', at=store.stamp(), correlationId=ctx.message,
          messageId=json.loads(template)['protected']['messageId'], operationId=op, instructionVersion=1,
          sender=ctx.sender, action=ctx.action, group=session.observation['group'], signatureProfile='ECDSA',
          policyVersion=1, keyId=outgoing.policy.signing_key_id, status=status, code=payload.get('code'))), flush=True)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with connect(CREDENTIAL, 'custodian', self.request, server=True, peer_dns='platform.cafi.test') as session:
            handle(session)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        print('{"service":"custodian","event":"exchange_failed"}', flush=True)


if __name__ == '__main__':
    incoming, outgoing = boundary(False, 'custodian'), boundary(True, 'custodian')
    with Server(('0.0.0.0', 8443), Handler) as server:
        server.serve_forever()
