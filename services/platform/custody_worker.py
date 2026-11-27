"""Durable C1 custody submission, resumption and authenticated polling."""
import argparse
import errno
import json
import math
from pathlib import Path
from random import uniform
import socket
from time import sleep

import h11
import psycopg

from c1.runtime import http, require
from c1.security import utc
from . import custody_store as store
from . import response_receipts
from .custody import Client, PreparationExpired
from .store import stamp

CREDENTIAL = Path('/custody-identity')
PASSWORD = Path('/credentials/platform/password')
CHECKS = frozenset(('response correlation', 'error correlation', 'invalid signature', 'result scope',
                    'inconsistent custodian snapshot', 'custody business mismatch', 'custody history gap',
                    'custody history regression', 'custody history changed', 'custodian error status',
                    'invalid custody transition', 'invalid local transition', 'response message ID reused',
                    'unexpected custody absence', 'envelope schema', 'validity', 'response media'))
VALIDATION = (ValueError, RuntimeError, TypeError, KeyError, OverflowError)
EXCHANGE = (*VALIDATION, OSError, http.TLSFailure, h11.ProtocolError, psycopg.Error)


def open_db():
    return psycopg.connect(host='db', user='platform', dbname='platform', autocommit=True,
                           password=PASSWORD.read_text(), connect_timeout=3)


def log(operation, action, result, *, request=None, response=None, **fields):
    print(json.dumps(dict(service='platform-custody', at=stamp(), operationId=operation,
                          instructionVersion=1, action=action, result=result,
                          correlationId=request, messageId=response, **fields)), flush=True)


def failure(exc):
    check = str(exc)
    if isinstance(exc, PreparationExpired):
        return 'PREPARATION_EXPIRED', True
    if isinstance(exc, TimeoutError):
        return 'TIMEOUT', True
    if isinstance(exc, http.TLSFailure):
        # Do not retry certificate, handshake policy or TLS protocol failures.
        info = exc.detail
        transport_lost = (info.get('verifyCode') == 0 and info['stage'] in ('read', 'write') and
                          (info.get('sslError') in (5, 6) or info.get('reason') == 'unexpected eof while reading'))
        return ('CONNECTION_LOST' if transport_lost else 'TLS_FAILURE'), transport_lost
    if isinstance(exc, OSError):
        # Unavailable service/DNS is transient; local key/file permissions are not.
        network = (isinstance(exc, ConnectionError) or
                   (isinstance(exc, socket.gaierror) and exc.errno in (socket.EAI_AGAIN, socket.EAI_NONAME)) or
                   exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT))
        return ('NETWORK_UNAVAILABLE' if network else type(exc).__name__), network
    if isinstance(exc, psycopg.Error):
        # Failed local response transaction: no effect was assumed, so query again.
        return exc.sqlstate or type(exc).__name__, True
    return (check if check in CHECKS else type(exc).__name__), isinstance(exc, store.HistoryGap)


class Worker:
    def __init__(self, client, interval=1, retry_base=1, jitter=0):
        self.client, self.interval, self.retry_base, self.jitter = client, interval, retry_base, jitter
        self.recipient = client.out.policy.recipient

    def delay(self, failures):
        return self.retry_base * 2**(failures-1) * (1 + uniform(-self.jitter, self.jitter))

    def record_failure(self, db, operation, job, attempt, code, retry, response=None, gap_through=None):
        delivery, delay = store.fail(db, operation, self.recipient, job, attempt, code,
                                     retry=retry, delays=self.delay, response=response, gap_through=gap_through)
        fields = dict(deliveryStatus=delivery, code=code, retryDelaySeconds=delay)
        if gap_through is not None:
            fields['gapThrough'] = gap_through
        return fields

    def reply(self, db, operation, job, attempt, action, response):
        status, content = response.status, response.content
        p, payload = content['protected'], content['payload']
        response_id = p['messageId']
        with db.transaction():
            require(response_receipts.register(db, response), 'response message ID reused')
            if action == store.KIND and status == 202:
                store.receive(db, operation, self.recipient, self.interval)
                result, fields = 'RECEIVED', {}
            elif action == store.QUERY and status == 200:
                added = store.project(db, operation, self.recipient, job, payload, self.interval)
                result, fields = 'PROJECTED', dict(added=added, state=payload['state'])
            elif action == store.QUERY and status == 404:
                require(payload['code'] == 'NOT_FOUND' and payload['retryable'] is False, 'custodian error status')
                if (job.delivery == 'UNKNOWN' and job.attempts > 0 and job.gap_through is None and
                        store.latest(db, operation)['state'] == 'SENT'):
                    store.allow_submit(db, operation, self.recipient, response_id, utc(p['expiresAt']))
                    result, fields = 'NOT_FOUND', {}
                else:
                    result, fields = 'FAILED', self.record_failure(
                        db, operation, job, attempt, 'unexpected custody absence', False, response_id)
            else:
                result, fields = 'FAILED', self.record_failure(
                    db, operation, job, attempt, payload['code'], payload['retryable'], response_id)
            if result != 'FAILED':
                store.finish(db, attempt, result, response=response_id)
        log(operation, action, result, attemptId=attempt, request=p['requestMessageId'],
            response=response_id, status=status, **fields)
        return result != 'FAILED'

    def run_job(self, db, operation):
        recipient = self.recipient
        if not store.reserve(db, operation, recipient):
            return True
        with db.transaction():
            job = store.lock(db, operation, recipient)
            if job is None or job.delivery == 'BLOCKED' or store.latest(db, operation)['state'] in store.TERMINAL:
                return True
            interrupted = store.unfinished(db, operation, recipient)
            if interrupted:
                attempt, action, request = interrupted
                preflight_error = self.record_failure(db, operation, job, attempt, 'INTERRUPTED', True)
                prepared = None
            else:
                action = store.action_for(job)
                if action is None:
                    return True
                attempt = store.begin(db, operation, recipient, action, job)
                preflight_error = request = prepared = None
                try:
                    store.check_intent(job, recipient)
                    if action == store.KIND:
                        prepared = self.client.prepare_submission(operation, job.payload)
                except (*VALIDATION, OSError) as exc:
                    code, _ = failure(exc)
                    preflight_error = self.record_failure(db, operation, job, attempt, code, False)
                if prepared is not None:
                    store.submitted(db, operation, recipient, job, attempt, prepared)
                    request = prepared.context.message
        if preflight_error:
            log(operation, action, 'FAILED', attemptId=attempt, request=str(request) if request else None,
                **preflight_error)
            return False
        tags = dict(attemptId=attempt, participant=recipient, policyVersion=1,
                    keyId=self.client.out.policy.signing_key_id)
        try:
            if action == store.KIND:
                log(operation, action, 'SENT', request=request, attempt=job.attempts+1, **tags)
                response = self.client.submit(prepared, proof_expires=job.authority_expires)
            else:
                with self.client.connection() as session:
                    scope = (job.manager, job.boleta['portfolioId'])
                    route, wire, ctx = self.client.prepare(session, operation, None, lambda _: scope)
                    request = ctx.message
                    with db.transaction():
                        store.query_signed(db, attempt, request)
                    log(operation, action, 'QUERY', request=request, group=session.observation['group'],
                        protocol=session.observation['protocol'], ciphersuite=session.observation['ciphersuite'],
                        **tags)
                    response = self.client.send_verified(session, route, wire, ctx)
            return self.reply(db, operation, job, attempt, action, response)
        except EXCHANGE as exc:
            code, retry = failure(exc)
            with db.transaction():
                # If committing the reply was ambiguous, do not overwrite a committed result.
                pending = store.unfinished(db, operation, recipient)
                gap_through = exc.through if isinstance(exc, store.HistoryGap) else None
                fields = (self.record_failure(db, operation, job, attempt, code, retry, gap_through=gap_through)
                          if pending and pending[0] == attempt else dict(code=code))
            log(operation, action, 'FAILED', attemptId=attempt, request=request, **fields)
            return False

    def cycle(self):
        try:
            with open_db() as db:
                ready = store.ready(db, self.recipient)
        except psycopg.Error as exc:
            log(None, 'SCAN', 'FAILED', code=failure(exc)[0])
            return 1
        errors = 0
        for operation, in ready:
            operation = str(operation)
            try:
                with open_db() as db:
                    errors += not self.run_job(db, operation)
            except EXCHANGE as exc:
                errors += 1
                log(operation, 'WORK', 'FAILED', code=failure(exc)[0])
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--poll-interval', type=float, default=1)
    parser.add_argument('--connect-timeout', type=float, default=3)
    parser.add_argument('--exchange-timeout', type=float, default=10)
    parser.add_argument('--retry-base', type=float, default=1)
    parser.add_argument('--retry-jitter', type=float, default=0, help='fraction in [0, 1)')
    args = parser.parse_args()
    if any(not math.isfinite(n) or n <= 0 for n in
           (args.poll_interval, args.connect_timeout, args.exchange_timeout, args.retry_base)):
        parser.error('intervals and timeouts must be finite and positive')
    if not 0 <= args.retry_jitter < 1:
        parser.error('retry jitter must be in [0, 1)')
    worker = Worker(Client(CREDENTIAL, connect_timeout=args.connect_timeout,
                           exchange_timeout=args.exchange_timeout), args.poll_interval,
                    args.retry_base, args.retry_jitter)
    if args.once:
        return int(worker.cycle() != 0)
    while True:
        worker.cycle()
        sleep(min(0.25, args.poll_interval))


if __name__ == '__main__':
    raise SystemExit(main())
