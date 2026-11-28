"""Instrument the real administrator after commit, only in the isolated test project."""
from base64 import b64decode, b64encode
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from time import sleep
from uuid import uuid4

import h11
from lxml import etree

from c1.security import SOAP
from c1.soap import C, S
from c1.transport import send_response
from services.administrator import serve

MODE = Path('/tmp/s2-12-mode')


def reply(session, signer, route, request, template, secret, status):
    mode = MODE.read_text().strip() if MODE.exists() else 'pass'
    obs = session.observation
    witness = dict(event='s2-12-transaction', mode=mode, action=request.action, operationId=request.operation,
                   correlationId=request.message, status=status, group=obs['group'], protocol=obs['protocol'],
                   ciphersuite=obs['ciphersuite'], peerDnsSan=obs['peerDnsSan'], verifyCode=obs['verifyCode'])
    print(json.dumps(witness), flush=True)
    if (mode == 'lose-register' and request.action == 'REGISTER_OPERATION' and status == 200
            or mode == 'lose-get' and request.action == 'QUERY_ADMIN_RECORD' and status == 200):
        # Commit happened in serve.transact; no response bytes are written.
        sleep(15)
        return
    root = etree.fromstring(template)
    if status == 200 and mode == 'business':
        root.find(f'.//{C}NegotiatedRate').text = '6.750000'
        template = etree.tostring(root)
    if status == 200 and mode == 'gross':
        root.find(f'.//{C}GrossAmount').text = '98050.01'
        template = etree.tostring(root)
    if status == 200 and mode == 'correlation':
        request = replace(request, message=str(uuid4()))
        root.find(f'.//{C}RequestMessageId').text = request.message
        template = etree.tostring(root)
    if mode in ('signature', 'version', 'outside', 'correlation'):
        wire, _ = signer.sign(template, route, secret, session, request=request)
        root = etree.fromstring(wire)
        if mode == 'signature':
            node = root.find(f'.//{C}Signature')
            sig = b64decode(node.text)
            node.text = b64encode(sig[:-1] + bytes([sig[-1] ^ 1])).decode()
        if mode == 'version':
            root.find(f'.//{C}InstructionVersion').text = '2'
        if mode == 'outside':
            assert status >= 400
            root.find(f'.//{S}Value').text = 's:Receiver'
            root.find(f'.//{S}Text').text = 'FORBIDDEN' if root.find(f'.//{C}Code').text == 'NOT_FOUND' else 'NOT_FOUND'
        wire = etree.tostring(root)
        session.link.send(h11.Response(status_code=status, headers=[
            ('Content-Type', SOAP), ('Content-Length', str(len(wire)))]), wire)
    else:
        wire = send_response(session, signer, route, request, template, secret, status)
    root = etree.fromstring(wire)
    print(json.dumps(dict(event='s2-12-wire', request=witness['correlationId'],
                          messageId=root.findtext(f'.//{C}MessageId'), digest=sha256(wire).hexdigest(),
                          code=root.findtext(f'.//{C}Code'), mode=mode)), flush=True)


if __name__ == '__main__':
    serve.send_response = reply
    with serve.Server(('0.0.0.0', 8443), serve.Handler) as server:
        server.boundaries = serve.boundary(False, 'administrator'), serve.boundary(True, 'administrator')
        server.serve_forever()
