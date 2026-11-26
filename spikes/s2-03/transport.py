"""One HTTP/1.1 exchange per directly authenticated TLS connection."""
from contextlib import contextmanager
import ctypes as c
from dataclasses import dataclass
from time import monotonic

import h11

if __package__:
    from spikes.tls.proof import require
else:
    from proof import require  # standalone gate


class TLSFailure(Exception):
    def __init__(self, stage, result):
        super().__init__(stage, result)
        self.detail = {'stage': stage, **result}


class Channel:
    def __init__(self, api, ssl, sock, deadline, role, limit):
        self.api, self.ssl, self.sock, self.deadline = api, ssl, sock, deadline
        self.http = h11.Connection(role, max_incomplete_event_size=16384)
        self.limit = limit

    def io(self, stage, op, *args):
        result = self.api.io(op, self.ssl, self.sock, self.deadline, *args)
        if result['return'] != 1:
            raise TLSFailure(stage, result)

    def send(self, headers, body):
        require(len(body) <= self.limit, 'outbound body limit')
        for event in (headers, h11.Data(data=body), h11.EndOfMessage()):
            data = self.http.send(event)
            while data:
                count = c.c_size_t()
                self.io('write', self.api.SSL_write_ex, data, len(data), c.byref(count))
                require(0 < count.value <= len(data), 'short TLS write without progress')
                data = data[count.value:]

    def receive(self, header_type):
        # Require bounded, length-delimited bodies for both adapters.
        head, body, length = None, bytearray(), None
        while True:
            event = self.http.next_event()
            if event is h11.NEED_DATA:
                buf, count = c.create_string_buffer(8192), c.c_size_t()
                self.io('read', self.api.SSL_read_ex, buf, len(buf), c.byref(count))
                require(count.value > 0, 'empty TLS read')
                self.http.receive_data(buf.raw[:count.value])
            elif isinstance(event, header_type) and head is None:
                head = event
                lengths = [v for k, v in head.headers if k == b'content-length']
                require(len(lengths) == 1 and len(lengths[0]) <= 10 and lengths[0].isdigit()
                        and not any(k == b'transfer-encoding' for k, _ in head.headers),
                        'expected Content-Length framing')
                length = int(lengths[0])
                require(length <= self.limit, 'inbound body limit')
            elif isinstance(event, h11.Data) and head is not None:
                require(len(body) + len(event.data) <= length, 'inbound body length')
                body.extend(event.data)
            elif isinstance(event, h11.EndOfMessage) and head is not None:
                require(len(body) == length and not event.headers, 'incomplete body or trailers')
                return head, bytes(body)
            else:
                raise ValueError('unexpected HTTP event')


@contextmanager
def channel(api, ctx, sock, *, server, group, peer, limit, timeout=10):
    with api.connection(ctx, sock, peer) as ssl:
        link = Channel(api, ssl, sock, monotonic() + timeout, h11.SERVER if server else h11.CLIENT, limit)
        link.io('handshake', api.SSL_accept if server else api.SSL_connect)
        def observe():
            return api.observed(ssl, group, peer)
        identity = observe()
        yield link, identity
        require(observe() == identity, 'TLS observations changed during HTTP exchange')


@dataclass(frozen=True)
class Endpoint:
    path: bytes
    request_type: bytes
    response_type: bytes
    status: int

    def headers(self, media, body):
        return [(b'Content-Type', media), (b'Content-Length', str(len(body)).encode())]

    def check_media(self, head, media):
        require([v for k, v in head.headers if k == b'content-type'] == [media], 'content type/action')

    def post(self, link, host, body):
        head = h11.Request(method=b'POST', target=self.path, headers=[
            (b'Host', host.encode()), *self.headers(self.request_type, body)])
        link.send(head, body)
        head, result = link.receive(h11.Response)
        require(head.status_code == self.status, 'unexpected HTTP response')
        self.check_media(head, self.response_type)
        return result

    def serve(self, link, handler):
        head, body = link.receive(h11.Request)
        require(head.method == b'POST' and head.target == self.path, 'method/path')
        self.check_media(head, self.request_type)
        result = handler(body)
        link.send(h11.Response(status_code=self.status, headers=self.headers(self.response_type, result)), result)
