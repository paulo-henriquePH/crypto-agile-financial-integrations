"""Pause the real worker after durable preparation but before opening a socket."""
from datetime import UTC, datetime, timedelta
from threading import Event

from services.platform import custody, custody_worker

original = custody.envelope


def short_envelope(policy, typ, *args, **kwargs):
    assert typ == 'SUBMIT_INSTRUCTION'
    end = (datetime.now(UTC) + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
    return original(policy, typ, *args, **kwargs, expiresAt=end)


def stall(*_, **__):
    print('stalled-before-socket', flush=True)
    Event().wait()


if __name__ == '__main__':
    custody.envelope = short_envelope
    custody.Client.submit = stall
    raise SystemExit(custody_worker.main())
