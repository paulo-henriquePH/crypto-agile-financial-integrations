"""C1 initial send and normal authenticated polling; no recovery or retransmission."""
import argparse
import json
import math
from pathlib import Path
from time import sleep

import h11
import psycopg

from c1.runtime import http
from . import custody_store as store
from . import response_receipts
from .custody import Client
from .store import stamp

CREDENTIAL = Path('/custody-identity')
PASSWORD = Path('/credentials/platform/password')
CHECKS = frozenset(('response correlation', 'error correlation', 'invalid signature', 'result scope',
                    'inconsistent custodian snapshot', 'custody business mismatch',
                    'custody history regression', 'custody history changed',
                    'invalid custody transition', 'invalid local transition', 'response message ID reused'))


def open_db():
    return psycopg.connect(host='db', user='platform', dbname='platform',
                           password=PASSWORD.read_text(), connect_timeout=3)


def log(operation, action, result, *, request=None, response=None, **fields):
    print(json.dumps(dict(service='platform-custody', at=stamp(), operationId=operation,
                          instructionVersion=1, action=action, result=result,
                          correlationId=request, messageId=response, **fields)), flush=True)


class Worker:
    def __init__(self, client, interval=1):
        self.client, self.interval = client, interval
        self.recipient = client.out.policy.recipient

    def submit(self, operation):
        with open_db() as db:
            prepared = store.prepare(db, operation, self.recipient, self.client.prepare_submission)
        # Closing this transaction successfully is a prerequisite to even opening the socket.
        if prepared is None:
            return True
        wire, ctx = prepared[1:3]
        log(operation, ctx.action, 'SENT', request=ctx.message, attempt=1, participant=self.recipient,
            policyVersion=1, keyId=self.client.out.policy.signing_key_id)
        response = self.client.submit(prepared)
        status, reply = response.status, response.content
        p = reply['protected']
        with open_db() as db:
            if response_receipts.register(db, response) and status == 202:
                store.receive(db, operation, self.recipient, wire, self.interval)
        if status != 202:
            log(operation, ctx.action, 'ERROR', request=ctx.message, response=p['messageId'],
                status=status, code=reply['payload']['code'])
            return False
        log(operation, ctx.action, 'RECEIVED', request=ctx.message, response=p['messageId'], status=status)
        return True

    def poll(self, operation):
        with open_db() as db:
            scope = store.claim_query(db, operation, self.recipient)
        if scope is None:
            return True
        with self.client.connection() as session:
            route, wire, ctx = self.client.prepare(session, operation, None, lambda _: scope)
            log(operation, ctx.action, 'QUERY', request=ctx.message, participant=self.recipient,
                policyVersion=1, keyId=self.client.out.policy.signing_key_id,
                group=session.observation['group'], protocol=session.observation['protocol'],
                ciphersuite=session.observation['ciphersuite'])
            response = self.client.send_verified(session, route, wire, ctx)
        status, reply = response.status, response.content
        p, history = reply['protected'], reply['payload']
        added = 0
        with open_db() as db:
            if response_receipts.register(db, response) and status == 200:
                added = store.project(db, operation, self.recipient, history, self.interval)
        if status != 200:
            log(operation, ctx.action, 'ERROR', request=ctx.message, response=p['messageId'],
                status=status, code=history['code'])
            return False
        log(operation, ctx.action, 'PROJECTED', request=ctx.message, response=p['messageId'],
            status=status, added=added, state=history['state'])
        return True

    def cycle(self):
        with open_db() as db:
            ready = store.ready(db, self.recipient)
        errors = 0
        for operation, first in ready:
            operation = str(operation)
            try:
                errors += not (self.submit(operation) if first else self.poll(operation))
            except (ValueError, RuntimeError, OSError, http.TLSFailure, h11.ProtocolError, psycopg.Error) as exc:
                errors += 1
                check = str(exc)
                code = check if check in CHECKS else getattr(exc, 'sqlstate', None) or type(exc).__name__
                log(operation, 'SUBMIT_INSTRUCTION' if first else 'QUERY_INSTRUCTION', 'FAILED', code=code)
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--poll-interval', type=float, default=1)
    parser.add_argument('--connect-timeout', type=float, default=3)
    parser.add_argument('--exchange-timeout', type=float, default=10)
    args = parser.parse_args()
    if any(not math.isfinite(n) or n <= 0 for n in
           (args.poll_interval, args.connect_timeout, args.exchange_timeout)):
        parser.error('interval and timeouts must be finite and positive')
    worker = Worker(Client(CREDENTIAL, connect_timeout=args.connect_timeout,
                           exchange_timeout=args.exchange_timeout), args.poll_interval)
    if args.once:
        return int(worker.cycle() != 0)
    while True:
        worker.cycle()
        sleep(min(0.25, args.poll_interval))


if __name__ == '__main__':
    raise SystemExit(main())
