"""Candidate body parsers. Transport supplies raw bytes and local trust separately."""
import base64
from dataclasses import dataclass
import json
from pathlib import Path
from xml.parsers import expat

from lxml import etree
import rfc8785

MAX_BYTES = 256 * 1024
MAX_DEPTH = 32
C = '{urn:cafi:v1}'
S = '{http://www.w3.org/2003/05/soap-envelope}'
PROFILES = {'ECDSA': ['ECDSA-P256-SHA256'], 'ML_DSA': ['ML-DSA-65'],
            'DUAL': ['ECDSA-P256-SHA256', 'ML-DSA-65']}
FINANCIAL = {'quantity', 'unitPrice', 'grossAmount', 'issueRate', 'negotiatedRate'}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def utf8(data):
    require(len(data) <= MAX_BYTES, 'size')
    return data.decode('utf-8')


def json_document(data):
    def unique(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), 'duplicate property')
        return obj

    def walk(node, depth):
        require(depth <= MAX_DEPTH, 'depth')
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        for child in children:
            walk(child, depth + 1)

    try:
        obj = json.loads(utf8(data), object_pairs_hook=unique,
                         parse_constant=lambda _: require(False, 'non-JSON number'))
    except RecursionError:
        raise ValueError('depth') from None
    walk(obj, 1)
    return obj


@dataclass
class Parsed:
    content: object
    canonical: bytes
    profile: str
    signatures: list


def checked(content, canonicalize, profile, signers, signatures):
    require(isinstance(profile, str) and profile in PROFILES, 'profile')
    require(isinstance(signers, list) and isinstance(signatures, list)
            and len(PROFILES[profile]) == len(signers) == len(signatures), 'signature count')
    entries = []
    for alg, signer, entry in zip(PROFILES[profile], signers, signatures):
        require(isinstance(entry, dict) and set(entry) == {'algorithm', 'keyId', 'value'}
                and entry['algorithm'] == alg and isinstance(entry['keyId'], str)
                and signer == {'algorithm': alg, 'keyId': entry['keyId']}, 'signer')
        require(isinstance(entry['value'], str), 'base64')
        raw = base64.b64decode(entry['value'], validate=True)
        require(raw and base64.b64encode(raw).decode() == entry['value'], 'base64')
        entries.append((alg, entry['keyId'], raw))
    return Parsed(content, canonicalize(content), profile, entries)


def parse_json(data):
    env = json_document(data)
    require(isinstance(env, dict) and set(env) == {'protected', 'payload', 'signatures'}, 'envelope')
    p, payload = env['protected'], env['payload']
    require(isinstance(p, dict) and isinstance(payload, dict) and p.get('canonicalization') == 'JCS',
            'JSON containers or canonicalization')

    def check_fields(node):
        if isinstance(node, dict):
            for k, value in node.items():
                require(k not in FINANCIAL or isinstance(value, str), 'financial string')
                check_fields(value)
        elif isinstance(node, list):
            for item in node:
                check_fields(item)

    check_fields(payload)
    return checked({'protected': p, 'payload': payload}, rfc8785.dumps,
                   p.get('signatureProfile'), p.get('signers'), env['signatures'])


def xml_preflight(data):
    utf8(data)
    require(b'\0' not in data, 'encoding')
    parser = expat.ParserCreate('UTF-8', ' ')
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    path = []
    def start(tag, attrs):
        path.append(tag)
        require(len(path) <= MAX_DEPTH, 'depth')
        require(not tag.startswith('http://www.w3.org/2001/XInclude '), 'xinclude')
        for attr in attrs:
            require(not attr.startswith('http://www.w3.org/2001/XMLSchema-instance '), 'schema hint')
            if attr.startswith('http://www.w3.org/XML/1998/namespace '):
                require(attr.endswith(' lang') and path == [
                    S[1:-1] + ' ' + n for n in ('Envelope', 'Body', 'Fault', 'Reason', 'Text')
                ], 'xml attribute')
    parser.StartElementHandler = start
    parser.EndElementHandler = lambda _: path.pop()
    parser.XmlDeclHandler = lambda v, enc, _: require(v == '1.0' and (enc or 'UTF-8').upper() == 'UTF-8', 'encoding')
    parser.StartDoctypeDeclHandler = lambda *_: require(False, 'doctype')
    parser.ProcessingInstructionHandler = lambda *_: require(False, 'processing instruction')
    try:
        parser.Parse(data, True)
    except expat.ExpatError:
        raise ValueError('XML syntax') from None


def soap_schema(contracts):
    paths = {p.resolve() for p in (contracts / 'soap/envelope.xsd', contracts / 'soap/administrator.xsd',
                                   contracts / 'schemas/xml/signed-content.xsd')}
    class LocalOnly(etree.Resolver):
        def resolve(self, url, public_id, context):
            require(Path(url).resolve() in paths, 'untrusted schema')
            return self.resolve_filename(url, context)
    parser = etree.XMLParser(no_network=True, resolve_entities=False, load_dtd=False)
    parser.resolvers.add(LocalOnly())
    return etree.XMLSchema(etree.parse(str((contracts / 'soap/envelope.xsd').resolve()), parser))


def c14n(node):
    return etree.tostring(node, method='c14n', exclusive=True, with_comments=False)


def text(node):
    return ''.join(node.itertext())


def parse_xml(data, schema):
    xml_preflight(data)
    root = etree.fromstring(data, etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False,
                                                  remove_blank_text=False, remove_comments=False))
    require(root.tag == S + 'Envelope' and schema.validate(root), 'soap schema')
    body = root.find(S + 'Body')
    message = body.find(C + 'Message')
    if message is None:
        message = body.find(S + 'Fault/' + S + 'Detail/' + C + 'Message')
    content = message.find(C + 'SignedContent')
    p = content.find(C + 'Protected')
    require(text(p.find(C + 'Canonicalization')) == 'EXCLUSIVE_C14N_1_0', 'XML canonicalization')
    signers = [dict(n.attrib) for n in p.findall(C + 'Signers/' + C + 'Signer')]
    entries = [{**n.attrib, 'value': text(n)} for n in message.findall(C + 'Signatures/' + C + 'Signature')]
    return checked(content, c14n, text(p.find(C + 'SignatureProfile')), signers, entries)


def receive(data, parse, crypto, profile, trusted, consume):
    """Only release parsed content after every locally required signature verifies."""
    message = parse(data)
    require(message.profile == profile, 'unexpected profile')
    for alg, kid, raw in message.signatures:
        require((alg, kid) in trusted, 'untrusted signer')
        require(crypto.verify(alg, trusted[alg, kid], message.canonical, raw), 'invalid signature')
    return consume(message.content)
