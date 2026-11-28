"""Run the candidate body adapters against frozen wire data and ephemeral EVP keys."""
import base64
from contextlib import ExitStack
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import sys
from unittest.mock import patch

import envelopes as e

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/contracts'))
from signed_crypto import OpenSSL, LIBRARY

VECTORS = ROOT / 'contracts/vectors'


def check(ok, name):
    if not ok:
        raise AssertionError(name)


def rejected(call, reason=None):
    try:
        call()
    except (ValueError, e.rfc8785.CanonicalizationError) as exc:
        if reason is not None:
            check(str(exc) == reason, f'expected {reason}, got {exc}')
    else:
        raise AssertionError('invalid input accepted')


def load(path):
    return json.loads(path.read_bytes())


def canonical_vectors(parse_xml):
    results = {}
    for fmt in ('json', 'xml'):
        directory = VECTORS / fmt
        for case in load(directory / 'manifest.json')['cases']:
            wire = (directory / case['input']).read_bytes()
            def run():
                if fmt == 'xml':
                    return parse_xml(wire).canonical
                if case['mode'] == 'document':
                    return e.rfc8785.dumps(e.json_document(wire))
                return e.parse_json(wire).canonical
            name = fmt + '/' + case['name']
            if 'expected' not in case:
                rejected(run)
                results[name] = 'rejected'
            else:
                ref = (directory / case['expected']).read_bytes()
                if fmt == 'xml':
                    ref = base64.b64decode(ref.strip(), validate=True)
                check(run() == ref and hashlib.sha256(ref).hexdigest() == case['sha256'], name)
                results[name] = 'exact'
    return results


class ObservedSchema:
    """Observe the real XSD validation tree at the boundary; do not replace the verdict."""
    def __init__(self):
        self.schema = e.soap_schema(ROOT / 'contracts')

    def validate(self, root):
        self.root = root
        return self.schema.validate(root)


def main():
    crypto = OpenSSL()
    check(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'platform')
    check(version('lxml') == '6.1.3' and version('rfc8785') == '0.1.4', 'parser versions')
    schema = ObservedSchema()
    def xml(data):
        return e.parse_xml(data, schema)
    results = canonical_vectors(xml)
    corpus = VECTORS / 'signed/corpus'
    keys = load(corpus / 'trust.json')['keys']
    manifest = load(corpus / 'manifest.json')['vectors']
    seen, fresh, negatives = [], [], []

    for case in manifest:
        name, profile, role = case['integration'], case['profile'], case['role']
        stem = f'{name}-{profile.lower()}-{role}'
        is_xml = name == 'administrator'
        parse = xml if is_xml else e.parse_json
        wire = (corpus / case['wire']).read_bytes()
        expected = base64.b64decode((corpus / case['canonical']).read_bytes().strip(), validate=True)
        sample = parse(wire)
        check(sample.canonical == expected and hashlib.sha256(expected).hexdigest() == case['sha256'], stem)
        sender = {'administrator': ('PLATFORM', 'ADMINISTRADOR-DELTA'),
                  'custodian': ('PLATFORM', 'CUSTODIANTE-GAMA'),
                  'platform': ('GESTORA-ALFA', 'PLATFORM')}[name][role != 'request']
        trusted = {(k['algorithm'], k['keyId']): base64.b64decode(k['public'], validate=True)
                   for k in keys if k['senderId'] == sender}

        def accept(data, registry):
            def consume(content):
                if is_xml:
                    nodes = list(schema.root.iter(e.C + 'SignedContent'))
                    check(len(nodes) == 1 and nodes[0] is content and canonical.call_args.args[0] is content,
                          'XSD/C14N/consumer node identity')
                    check(content.find(e.C + 'Payload') is not None, 'consumer payload')
                else:
                    check(isinstance(content['payload'], dict), 'consumer payload')
            with patch.object(e, 'c14n', wraps=e.c14n) as canonical:
                e.receive(data, parse, crypto, profile, registry, consume)

        accept(wire, trusted)
        seen.append(stem)
        if role != 'request' or name == 'custodian':
            continue

        def deny(data, registry, why):
            rejected(lambda: e.receive(data, parse, crypto, profile, registry,
                                       lambda _: sys.exit('invalid input reached consumer')), why)

        # Re-sign with new native private handles; install only SPKIs at the receiver.
        new_wire, public = wire, {}
        with ExitStack() as owner:
            for alg, kid, old in sample.signatures:
                key = owner.enter_context(crypto.generate(alg))
                public[alg, kid] = crypto.export_public(key)
                signature = crypto.sign(alg, key, sample.canonical)
                old64 = base64.b64encode(old)
                check(new_wire.count(old64) == 1, 'signature slot')
                new_wire = new_wire.replace(old64, base64.b64encode(signature))
        accept(new_wire, public)
        fresh.append(stem)
        deny(new_wire, trusted, 'invalid signature')
        deny(new_wire, {}, 'untrusted signer')
        changed = new_wire.replace(b'OP-000001', b'OP-000002', 1)
        check(changed != new_wire, 'payload mutation')
        deny(changed, public, 'invalid signature')
        for alg, _, signature in parse(new_wire).signatures:
            bad = signature[:-1] + bytes([signature[-1] ^ 1])
            deny(new_wire.replace(base64.b64encode(signature), base64.b64encode(bad)), public,
                 'invalid signature')
            negatives.append(stem + '/signature/' + alg)
        negatives.extend(stem + '/' + n for n in ('wrong-key', 'untrusted', 'payload'))

    check(len(set(seen)) == len(seen) == 27 and len(set(fresh)) == 6, 'inventory')
    for fmt, parse, deep in [('xml', xml, b'<a>' * 33 + b'</a>' * 33),
                             ('json', e.parse_json, b'[' * 33 + b']' * 33)]:
        for label, wire in [('size', b' ' * (e.MAX_BYTES + 1)), ('depth', deep)]:
            rejected(lambda: parse(wire), label)
            negatives.append(fmt + '/' + label)
    print(json.dumps({
        'task': 'S2-02', 'baseRevision': 'bff11109ab471313d597347dd9d16fa919827907',
        'checkoutRevision': os.environ['CAFI_CODE_REVISION'],
        'provenance': 'baseRevision precedes S2-02; sourcesSHA256 identifies the candidate Python files executed',
        'imageId': os.environ['CAFI_IMAGE_ID'], 'platform': 'linux/amd64',
        'runtime': platform.python_version(), 'openssl': crypto.version,
        'libcryptoSHA256': hashlib.sha256(LIBRARY.read_bytes()).hexdigest(),
        'lxml': version('lxml'), 'libxml2': e.etree.LIBXML_VERSION, 'rfc8785': version('rfc8785'),
        'sourcesSHA256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in [Path(__file__), Path(e.__file__)]},
        'canonical': results, 'static': seen, 'fresh': fresh, 'rejections': negatives,
        'result': 'passed',
    }, indent=2))


if __name__ == '__main__':
    main()
