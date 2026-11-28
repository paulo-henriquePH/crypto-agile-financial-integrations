"""Read the independent administrator record and compare verified snapshots."""
import argparse
import json
import math
from random import uniform
from time import sleep

from . import reconciliation_store as store
from .administrator import Client
from .administrator_store import GET
from .administrator_worker import classify
from .custody_worker import EXCHANGE, open_db
from .store import stamp


def log(operation, version, result, **fields):
    print(json.dumps(dict(service='platform-reconciliation', at=stamp(), operationId=operation,
                          instructionVersion=version, action=GET, result=result, **fields)), flush=True)


class Worker:
    def __init__(self, client, absence_interval=16, retry_base=1, jitter=0):
        self.client, self.recipient = client, client.out.policy.recipient
        self.absence_interval, self.retry_base, self.jitter = absence_interval, retry_base, jitter

    def failure(self, db, operation, version, job, code, retry):
        failures = job.failures + int(retry)
        delay = self.retry_base * 2**(failures-1) * (1 + uniform(-self.jitter, self.jitter)) if retry else 0
        store.defer(db, operation, version, failures, code, delay, blocked=not retry or failures >= 5)
        return dict(code=code, retryDelaySeconds=delay, blocked=not retry or failures >= 5)

    def run_job(self, db, operation, version):
        if not store.reserve(db, operation, version):
            return True
        job = store.due(db, operation, version, self.recipient)
        if job is None:
            return True
        fields = {}
        try:
            # A new signed GetOperation from the immutable local scope. This
            # path never uses the publication attempt, payload or ACK.
            response = self.client.exchange(operation, job.scope)
            p, obs = response.content['protected'], response.observation
            fields = dict(correlationId=p['requestMessageId'], messageId=p['messageId'], participant=p['senderId'],
                          keyId=p['signers'][0]['keyId'], policyVersion=p['policyVersion'],
                          signatureProfile=p['signatureProfile'], group=obs['group'], protocol=obs['protocol'],
                          ciphersuite=obs['ciphersuite'], peerDnsSan=obs['peerDnsSan'], verifyCode=obs['verifyCode'])
            with db.transaction():
                status = store.record(db, operation, version, job, response)
                if status == 'NOT_READY':
                    store.defer(db, operation, version, 0, 'NOT_FOUND', self.absence_interval)
                    fields['code'] = 'NOT_FOUND'
                elif status is None:
                    payload = response.content['payload']
                    fields.update(self.failure(db, operation, version, job, payload['code'], payload['retryable']))
        except EXCHANGE as exc:
            status = None
            fields.update(self.failure(db, operation, version, job, *classify(exc)))
        log(operation, version, status or 'FAILED', **fields)
        return status is not None

    def cycle(self):
        errors = 0
        try:
            with open_db() as db:
                ready = store.ready(db, self.recipient)
        except EXCHANGE as exc:
            log(None, None, 'FAILED', code=classify(exc)[0])
            return 1
        for operation, version in ready:
            operation = str(operation)
            try:
                with open_db() as db:
                    errors += not self.run_job(db, operation, version)
            except EXCHANGE as exc:
                errors += 1
                log(operation, version, 'FAILED', code=classify(exc)[0])
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--connect-timeout', type=float, default=3)
    parser.add_argument('--exchange-timeout', type=float, default=10)
    parser.add_argument('--absence-interval', type=float, default=16)
    parser.add_argument('--retry-base', type=float, default=1)
    parser.add_argument('--retry-jitter', type=float, default=0)
    args = parser.parse_args()
    times = args.connect_timeout, args.exchange_timeout, args.absence_interval, args.retry_base
    if any(not math.isfinite(v) or v <= 0 for v in times):
        parser.error('timeouts and delays must be finite and positive')
    if not 0 <= args.retry_jitter < 1:
        parser.error('retry jitter must be in [0, 1)')
    worker = Worker(Client(connect_timeout=args.connect_timeout, exchange_timeout=args.exchange_timeout),
                    args.absence_interval, args.retry_base, args.retry_jitter)
    if args.once:
        return int(worker.cycle() != 0)
    while True:
        worker.cycle()
        sleep(.25)


if __name__ == '__main__':
    raise SystemExit(main())
