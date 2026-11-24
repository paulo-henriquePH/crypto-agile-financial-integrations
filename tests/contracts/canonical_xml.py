"""S1-13: parse a fixed SOAP-shaped test envelope and check XML C14N vectors."""

import argparse
import base64
from binascii import Error as Base64Error
from datetime import date, datetime
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import sys
from xml.parsers import expat

from lxml import etree

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / 'contracts/vectors/xml'
MAX_BYTES = 256 * 1024
MAX_DEPTH = 32
SOAP = 'http://www.w3.org/2003/05/soap-envelope'
CAFI = 'urn:cafi:v1'
XI = 'http://www.w3.org/2001/XInclude'
XSI = 'http://www.w3.org/2001/XMLSchema-instance'
XML = 'http://www.w3.org/XML/1998/namespace'


class XmlRejected(ValueError):
    """Only report a stable rejection code, not untrusted XML or URLs."""


def _preflight(data):
    if len(data) > MAX_BYTES:
        raise XmlRejected('size')
    # Expat aborts at the opening DOCTYPE, even before reading the internal subset.
    # Its parsed events also distinguish markup from literal text in CDATA/comments.
    parser = expat.ParserCreate('UTF-8', ' ')
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    depth = 0

    def reject(code):
        def handler(*_):
            raise XmlRejected(code)
        return handler

    def declaration(version, encoding, _standalone):
        if version != '1.0' or (encoding is not None and encoding.upper() != 'UTF-8'):
            raise XmlRejected('encoding')

    def start(name, attributes):
        nonlocal depth
        depth += 1
        if depth > MAX_DEPTH:
            raise XmlRejected('depth')
        if name.startswith(XI + ' '):
            raise XmlRejected('xinclude')
        if any(attr.startswith((XSI + ' ', XML + ' ')) for attr in attributes):
            raise XmlRejected('context-attribute')

    def end(_name):
        nonlocal depth
        depth -= 1

    parser.XmlDeclHandler = declaration
    parser.StartDoctypeDeclHandler = reject('doctype')
    parser.ExternalEntityRefHandler = reject('external-reference')
    parser.ProcessingInstructionHandler = reject('processing-instruction')
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        data.decode('utf-8', errors='strict')
        # Expat may auto-detect wide encodings even when no declaration is present.
        if b'\x00' in data:
            raise XmlRejected('encoding')
        parser.Parse(data, True)
    except UnicodeDecodeError:
        raise XmlRejected('encoding') from None
    except expat.ExpatError:
        raise XmlRejected('xml-syntax') from None


class _DenyExternal(etree.Resolver):
    def resolve(self, _url, _public_id, _context):
        raise XmlRejected('external-reference')


def _parser():
    parser = etree.XMLParser(
        encoding='UTF-8', load_dtd=False, dtd_validation=False, attribute_defaults=False,
        resolve_entities=False, no_network=True, huge_tree=False, recover=False,
        remove_blank_text=False, remove_comments=False, remove_pis=False, collect_ids=False,
    )
    parser.resolvers.add(_DenyExternal())
    return parser


@lru_cache(maxsize=1)
def _schema():
    # Single trusted repository XSD; no imports, dynamic schema hints, or wildcards.
    path = ROOT / 'contracts/schemas/xml/signed-content.xsd'
    return etree.XMLSchema(etree.fromstring(path.read_bytes(), _parser()), attribute_defaults=False)


def _tag(name):
    return f'{{{CAFI}}}{name}'


def _children(node):
    return [child for child in node if isinstance(child.tag, str)]


def _only(node, tags):
    children = _children(node)
    if (node.attrib or [child.tag for child in children] != tags
            or (node.text or '').strip(' \t\r\n')
            or any((child.tail or '').strip(' \t\r\n') for child in node)):
        raise XmlRejected('soap-path')
    return children


def _text(node):
    # Leaf validated by XSD: concatenate all runs, including ones split by a
    # comment. Reading only .text could give different values for identical C14N.
    return ''.join(node.itertext())


def _field(node, name):
    return node.find(_tag(name))


def _value(node, name):
    child = _field(node, name)
    return _text(child) if child is not None else None


def _check_fields(content, signatures):
    protected, payload = _children(content)
    kind = _value(protected, 'MessageType')
    request_id = _value(protected, 'RequestMessageId')
    if (request_id is not None) != (kind.endswith('_RESULT') or kind == 'ERROR'):
        raise XmlRejected('request-correlation')
    try:
        datetime.fromisoformat(_value(protected, 'IssuedAt'))
        datetime.fromisoformat(_value(protected, 'ExpiresAt'))
    except ValueError:
        raise XmlRejected('calendar') from None

    first = next(iter(_children(payload)), None)
    expected = (None if kind == 'QUERY_ADMIN_RECORD'
                else _tag('Code' if kind == 'ERROR' else 'ManagerId'))
    if (None if first is None else first.tag) != expected:
        raise XmlRejected('payload-type')
    if kind == 'ERROR':
        if _value(payload, 'CorrelationId') != request_id:
            raise XmlRejected('request-correlation')
    elif kind != 'QUERY_ADMIN_RECORD':
        state = _value(payload, 'State')
        if ((_field(payload, 'Reason') is not None) != (state in ('REJECTED', 'SETTLEMENT_FAILED'))
                or (_field(payload, 'RejectionOrigin') is not None) != (state == 'REJECTED')):
            raise XmlRejected('terminal-state')
        boleta = _field(payload, 'Boleta')
        try:
            date.fromisoformat(_value(boleta, 'TradeDate'))
            date.fromisoformat(_value(boleta, 'SettlementDate'))
        except ValueError:
            raise XmlRejected('calendar') from None

    signers = _children(_field(protected, 'Signers'))
    ecdsa, mldsa = 'ECDSA-P256-SHA256', 'ML-DSA-65'
    profiles = {'ECDSA': [ecdsa], 'ML_DSA': [mldsa], 'DUAL': [ecdsa, mldsa]}
    if [item.get('algorithm') for item in signers] != profiles[_value(protected, 'SignatureProfile')]:
        raise XmlRejected('signers')
    signature_nodes = _children(signatures)
    if [item.attrib for item in signers] != [item.attrib for item in signature_nodes]:
        raise XmlRejected('signers')
    for item in signature_nodes:
        value = _text(item)
        try:
            decoded = base64.b64decode(value, validate=True)
        except (Base64Error, ValueError):
            raise XmlRejected('signature-encoding') from None
        if base64.b64encode(decoded).decode('ascii') != value:
            raise XmlRejected('signature-encoding')


def canonical_message(data: bytes):
    """Return (node, canonical bytes); no signature or business verification."""
    _preflight(data)
    try:
        root = etree.fromstring(data, _parser())
    except etree.XMLSyntaxError:
        raise XmlRejected('xml-syntax') from None
    if root.getroottree().docinfo.doctype:
        raise XmlRejected('doctype')
    if root.tag != f'{{{SOAP}}}Envelope':
        raise XmlRejected('soap-path')
    body, = _only(root, [f'{{{SOAP}}}Body'])
    message, = _only(body, [_tag('Message')])
    content, signatures = _only(message, [_tag('SignedContent'), _tag('Signatures')])
    schema = _schema()
    if not schema.validate(content) or not schema.validate(signatures):
        raise XmlRejected('xsd')
    _check_fields(content, signatures)
    try:
        actual = etree.tostring(
            content, method='c14n', exclusive=True, with_comments=False, inclusive_ns_prefixes=None,
        )
    except etree.C14NError:
        raise XmlRejected('canonicalization') from None
    return content, actual


def check_expected(data, expected, sha256):
    """Check frozen bytes and digest, then hand back the exact node compared."""
    content, actual = canonical_message(data)
    if actual != expected or hashlib.sha256(actual).hexdigest() != sha256:
        raise XmlRejected('reference-mismatch')
    return content


def check_vector(case):
    data = (VECTORS / case['input']).read_bytes()
    try:
        if 'reject' not in case:
            expected = base64.b64decode((VECTORS / case['expected']).read_bytes().strip(), validate=True)
            return check_expected(data, expected, case['sha256'])
        canonical_message(data)
    except XmlRejected as exc:
        if str(exc) == case.get('reject'):
            return None
        raise ValueError(f"{case['name']}: unexpected rejection {exc}") from None
    raise ValueError(f"{case['name']}: unexpectedly accepted")


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument('--invalid', action='store_true', help='deliberately perturb the first expected digest')
    args = cli.parse_args()
    cases = json.loads((VECTORS / 'manifest.json').read_text(encoding='utf-8'))['cases']
    if args.invalid:
        next(case for case in cases if 'sha256' in case)['sha256'] = '0' * 64
    try:
        for case in cases:
            check_vector(case)
            print(f"{case['name']}: {case.get('reject', 'exact bytes and digest')}")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
