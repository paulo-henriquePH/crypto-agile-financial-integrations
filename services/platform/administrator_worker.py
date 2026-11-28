"""Publish and recover terminal SOAP records without updating financial state."""
import argparse
import json
import math
from random import uniform
from time import sleep

from c1.runtime import require
from c1.security import utc
from . import administrator_store as store, response_receipts
from .administrator import Client
from .custody_worker import EXCHANGE, failure, open_db
from .store import stamp

CHECKS = frozenset(('administrator outbox intent', 'administrator result business',
                    'administrator registration mismatch', 'administrator recovery mismatch',
                    'administrator fault semantics', 'response message ID reused',
                    'response correlation', 'error correlation', 'invalid signature', 'result scope',
                    'direction', 'validity', 'envelope schema', 'C1 version', 'response media',
                    'absence context', 'SOAP Fault status', 'result status', 'portfolio permission'))


def classify(exc):
    return (str(exc), False) if str(exc) in CHECKS else failure(exc)


def log(operation, action, result, **fields):
    print(json.dumps(dict(service='platform-administrator', at=stamp(), operationId=operation,
                          instructionVersion=1, action=action, result=result, **fields)), flush=True)


class Worker:
    def __init__(self, client, retry_base=1, jitter=0):
        self.client, self.retry_base, self.jitter = client, retry_base, jitter
        self.recipient = client.out.policy.recipient

    def delay(self, failures):
        return self.retry_base * 2**(failures-1) * (1 + uniform(-self.jitter, self.jitter))

    def fail(self, db, operation, job, attempt, code, retry, response=None):
        status, delay = store.fail(db, operation, self.recipient, job, attempt, code,
                                   retry=retry, delays=self.delay, response=response)
        return dict(code=code, deliveryStatus=status, retryDelaySeconds=delay)

    def reply(self, db, operation, job, attempt, action, response):
        p, payload = response.content['protected'], response.content['payload']
        mid = p['messageId']
        fields = dict(attemptId=attempt, correlationId=p['requestMessageId'], messageId=mid, status=response.status)
        with db.transaction():
            require(response_receipts.register(db, response, kind='ADMINISTRATOR_RESPONSE'), 'response message ID reused')
            if p['messageType'] != 'ERROR':
                # Recovery GetOperation must prove the exact persisted intent;
                # the separate reconciliation read deliberately does not do this.
                require(payload == job.payload, 'administrator recovery mismatch')
                store.confirm(db, operation, self.recipient)
                outcome = 'CONFIRMED'
            elif payload['code'] == 'NOT_FOUND':
                require(action == store.GET and job.status == 'UNKNOWN', 'absence context')
                store.allow_register(db, operation, self.recipient, mid, utc(p['expiresAt']))
                outcome = 'NOT_FOUND'
            else:
                outcome = 'FAILED'
                fields.update(self.fail(db, operation, job, attempt, payload['code'], payload['retryable'], mid))
            if outcome != 'FAILED':
                store.finish(db, attempt, outcome, response=mid)
        log(operation, action, outcome, **fields)
        return outcome != 'FAILED'

    def run_job(self, db, operation):
        recipient = self.recipient
        if not store.reserve(db, operation, recipient):
            return True
        interrupted = None
        with db.transaction():
            job = store.lock(db, operation, recipient)
            if not job or job.status not in ('PENDING', 'UNKNOWN') or not job.due:
                return True
            prior = store.unfinished(db, operation, recipient)
            if prior:
                attempt, action, mid = prior
                interrupted = self.fail(db, operation, job, attempt, 'INTERRUPTED', True)
            else:
                action = store.REGISTER if job.status == 'PENDING' or job.expires is not None else store.GET
                proof = job.authority if job.expires is not None else None
                attempt = store.begin(db, operation, recipient, action, proof)
        if interrupted:
            log(operation, action, 'FAILED', attemptId=attempt, correlationId=str(mid) if mid else None, **interrupted)
            return False
        mid = None

        def before_send(request, wire, observed):
            nonlocal mid
            mid = request.message
            with db.transaction():
                store.prepared(db, operation, recipient, attempt, action, mid, wire)
            log(operation, action, 'SENDING', attemptId=attempt, authorityId=str(proof) if proof else None,
                correlationId=mid, participant=recipient, policyVersion=1, keyId=self.client.out.policy.signing_key_id,
                signatureProfile='ECDSA', group=observed['group'], protocol=observed['protocol'],
                ciphersuite=observed['ciphersuite'], peerDnsSan=observed['peerDnsSan'], verifyCode=observed['verifyCode'])

        try:
            job.check(recipient)
            response = self.client.exchange(operation, job.scope,
                                            payload=job.payload if action == store.REGISTER else None,
                                            before_send=before_send, proof_expires=job.expires)
            return self.reply(db, operation, job, attempt, action, response)
        except EXCHANGE as exc:
            code, retry = classify(exc)
            with db.transaction():
                # The outcome commit itself can fail ambiguously. Never
                # overwrite an already durable confirmation/absence.
                pending = store.unfinished(db, operation, recipient)
                fields = (self.fail(db, operation, job, attempt, code, retry)
                          if pending and pending[0] == attempt else dict(code=code))
            log(operation, action, 'FAILED', attemptId=attempt, correlationId=mid, **fields)
            return False

    def cycle(self):
        try:
            with open_db() as db:
                ready = store.ready(db, self.recipient)
        except EXCHANGE as exc:
            log(None, 'SCAN', 'FAILED', code=classify(exc)[0])
            return 1
        errors = 0
        for operation, in ready:
            operation = str(operation)
            try:
                with open_db() as db:
                    errors += not self.run_job(db, operation)
            except EXCHANGE as exc:
                errors += 1
                log(operation, 'WORK', 'FAILED', code=classify(exc)[0])
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--connect-timeout', type=float, default=3)
    parser.add_argument('--exchange-timeout', type=float, default=10)
    parser.add_argument('--retry-base', type=float, default=1)
    parser.add_argument('--retry-jitter', type=float, default=0)
    args = parser.parse_args()
    if any(not math.isfinite(v) or v <= 0 for v in (args.connect_timeout, args.exchange_timeout, args.retry_base)):
        parser.error('timeouts and retry base must be finite and positive')
    if not 0 <= args.retry_jitter < 1:
        parser.error('retry jitter must be in [0, 1)')
    worker = Worker(Client(connect_timeout=args.connect_timeout, exchange_timeout=args.exchange_timeout),
                    args.retry_base, args.retry_jitter)
    if args.once:
        return int(worker.cycle() != 0)
    while True:
        worker.cycle()
        sleep(.25)


if __name__ == '__main__':
    raise SystemExit(main())
