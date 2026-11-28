"""Pause the actual C1 channel after mTLS, before its first application write."""
from datetime import UTC, datetime, timedelta
import json
import os
from time import sleep

import h11

from c1.runtime import http
from services.platform import custody_worker


def pause(channel, head, wire, **kwargs):
    assert isinstance(head, h11.Request) and head.target == b'/v1/instructions'
    expiry = datetime.fromisoformat(os.environ['S2_10_PROOF_EXPIRES'])
    entered = datetime.now(UTC)
    assert entered < expiry, 'proof already expired at Channel.send entry'
    wake = expiry + timedelta(milliseconds=75)
    while (delay := (wake - datetime.now(UTC)).total_seconds()) > 0:
        sleep(delay)
    resumed = datetime.now(UTC)
    writes = 0
    original_write = channel.api.SSL_write_ex

    def observed_write(*args):
        nonlocal writes
        writes += 1
        return original_write(*args)

    channel.api.SSL_write_ex = observed_write
    try:
        return send(channel, head, wire, **kwargs)
    finally:
        channel.api.SSL_write_ex = original_write
        print(json.dumps(dict(event='before-first-tls-write', entered=entered.isoformat(),
                              expires=expiry.isoformat(), resumed=resumed.isoformat(), tlsWrites=writes)),
              flush=True)


if __name__ == '__main__':
    send = http.Channel.send
    http.Channel.send = pause
    raise SystemExit(custody_worker.main())
