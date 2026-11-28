"""Synthetic manager CLI, using the same verified exchange as the integration tests."""
import argparse
import json
import socket

from c1.runtime import ROOT, connect
from c1.security import JSON, Route
from c1.transport import receive_response, send_request
from .messages import CREDENTIAL, SECRET, boundary, envelope


def main():
    p = argparse.ArgumentParser()
    commands = p.add_subparsers(dest='command', required=True)
    commands.add_parser('create').add_argument('client_order_id')
    commands.add_parser('query').add_argument('operation_id')
    args = p.parse_args()
    out, back = boundary(False), boundary(True)
    if args.command == 'create':
        action, path, op = 'CREATE_OPERATION', '/v1/operations', None
        payload = json.loads((ROOT / 'fixtures/boletas/valid.json').read_bytes())
        payload['clientOrderId'] = args.client_order_id
    else:
        op = args.operation_id
        action, path, payload = 'QUERY_OPERATION', f'/v1/operations/{op}/status-queries', {}
    route = Route('POST', path, JSON)
    with socket.create_connection(('platform.cafi.test', 8443), timeout=5) as sock, connect(
            CREDENTIAL, 'manager', sock, server=False, peer_dns='platform.cafi.test') as session:
        # This CLI only accepts results belonging to its one configured laboratory portfolio.
        ctx = send_request(session, out, route, envelope(out.policy, action, payload, op), SECRET,
                           lookup=lambda _: ('GESTORA-ALFA', 'FUNDO-ALFA'))
        status, message = receive_response(session, back, route, ctx)
        print(json.dumps(dict(status=status, operationId=message['protected'].get('operationId'),
                              state=message['payload'].get('state'), code=message['payload'].get('code'))))
        return int(status >= 400)


if __name__ == '__main__':
    raise SystemExit(main())
