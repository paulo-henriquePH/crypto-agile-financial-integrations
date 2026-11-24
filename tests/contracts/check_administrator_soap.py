"""Offline SOAP contract checks; not a signature verifier or service."""
import argparse
import hashlib
from pathlib import Path
from urllib.parse import urlparse, unquote
from xml.parsers import expat

from lxml import etree
from zeep import Client, Settings
from zeep.transports import Transport
import canonical_xml as x

ROOT = x.ROOT
SOAPDIR = ROOT / 'contracts/soap'
WSDL = SOAPDIR / 'administrator.wsdl'
XSD = SOAPDIR / 'administrator.xsd'
ENVELOPE = SOAPDIR / 'envelope.xsd'
COMMON = ROOT / 'contracts/schemas/xml/signed-content.xsd'
REFERENCE = SOAPDIR / 'reference'
WSDL_SCHEMA = REFERENCE / 'wsdl-2003-02-11.xsd'
SOAP_SCHEMA = REFERENCE / 'wsdl11soap12.xsd'
VALIDATION_SCHEMA = REFERENCE / 'validation.xsd'
ALLOWED = {p.resolve() for p in (WSDL, XSD, ENVELOPE, COMMON, WSDL_SCHEMA, SOAP_SCHEMA, VALIDATION_SCHEMA)}
S = '{' + x.SOAP + '}'
C = '{' + x.CAFI + '}'
ACTION = 'urn:cafi:administrator:v1:'
W = '{http://schemas.xmlsoap.org/wsdl/}'
B = '{http://schemas.xmlsoap.org/wsdl/soap12/}'
REFERENCE_HASHES = {
    WSDL_SCHEMA: '5ba4c0d0c2804572f1afca3ecda2e9c66b98601d781519e404136fdf766573e6',
    SOAP_SCHEMA: '01ec1f55fd3aca2d1ed7a29f95fe6fbae659ce45fe71085259203b143b0fddac',
    VALIDATION_SCHEMA: 'bd0f5d7ac129f5124617362c86a733ec691239330c2321121c164b1c66c33520',
}


def allowed_path(url):
    u = urlparse(str(url))
    if u.scheme not in ('', 'file') or u.netloc:
        raise ValueError('remote import')
    p = Path(unquote(u.path)).resolve()
    if p not in ALLOWED:
        raise ValueError('unauthorized import')
    return p


class LocalTransport(Transport):
    def load(self, url):
        return allowed_path(url).read_bytes()

    def post(self, *args, **kwargs):
        raise ValueError('network disabled')


class LocalResolver(etree.Resolver):
    def resolve(self, url, public_id, context):
        return self.resolve_filename(str(allowed_path(url)), context)


def wsdl_structure(data, parser):
    """Validate upstream WSDL/SOAP XSDs, then enforce this contract's profile."""
    for path, digest in REFERENCE_HASHES.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('reference hash')
    validator = etree.XMLSchema(etree.parse(str(VALIDATION_SCHEMA), parser))
    x._preflight(data)
    root = etree.fromstring(data, x._parser())
    if not validator.validate(root):
        raise ValueError('invalid WSDL structure')
    binding_nodes = root.findall(W + 'binding')
    if len(binding_nodes) != 1:
        raise ValueError('binding count')
    binding = binding_nodes[0]
    soap_binding = binding.findall(B + 'binding')
    if (len(soap_binding) != 1 or soap_binding[0].get('transport') != 'http://schemas.xmlsoap.org/soap/http'
            or soap_binding[0].get('style') != 'document'):
        raise ValueError('SOAP binding')
    ops = binding.findall(W + 'operation')
    if len(ops) != 2 or {op.get('name') for op in ops} != {'RegisterOperation', 'GetOperation'}:
        raise ValueError('binding operations')
    for op in ops:
        extensions = op.findall(B + 'operation')
        if (len(extensions) != 1 or extensions[0].get('soapAction') != ACTION + op.get('name')
                or extensions[0].get('style', 'document') != 'document'):
            raise ValueError('SOAP action')
        for direction in ('input', 'output'):
            nodes = op.findall(W + direction)
            bodies = nodes[0].findall(B + 'body') if len(nodes) == 1 else []
            if (len(bodies) != 1 or bodies[0].get('use') != 'literal'
                    or bodies[0].get('encodingStyle') is not None):
                raise ValueError('SOAP body')
        faults = op.findall(W + 'fault')
        ext = faults[0].findall(B + 'fault') if len(faults) == 1 else []
        if (len(faults) != 1 or faults[0].get('name') != 'AdministratorFault'
                or len(ext) != 1 or ext[0].get('name') != 'AdministratorFault'
                or ext[0].get('use') != 'literal' or ext[0].get('encodingStyle') is not None):
            raise ValueError('SOAP fault')
    return root


def schema_and_client():
    # Fixed dependency graph: do not allow even another local file.
    parser = etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
    parser.resolvers.add(LocalResolver())
    for path in ALLOWED:
        x._preflight(path.read_bytes())
    wsdl_structure(WSDL.read_bytes(), parser)
    schema = etree.XMLSchema(etree.parse(str(ENVELOPE), parser))
    client = Client(str(WSDL), transport=LocalTransport(),
                    settings=Settings(forbid_dtd=True, forbid_entities=True, forbid_external=True))
    binding = client.wsdl.bindings['{urn:cafi:administrator:v1}AdministratorSoap12']
    if set(binding._operations) != {'RegisterOperation', 'GetOperation'}:
        raise ValueError('operations')
    for name, operation in binding._operations.items():
        if operation.soapaction != ACTION + name:
            raise ValueError('action')
    return schema, client


def preflight(data):
    # Same limits as S1-13, except SOAP 1.2 requires xml:lang on Reason/Text.
    if len(data) > x.MAX_BYTES or b'\x00' in data:
        raise ValueError('size or encoding')
    data.decode('utf-8')
    p = expat.ParserCreate('UTF-8', ' ')
    p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    stack = []
    def reject(*args):
        raise ValueError('unsafe XML')
    def declaration(version, encoding, standalone):
        if version != '1.0' or (encoding and encoding.upper() != 'UTF-8'):
            reject()
    def start(name, attrs):
        stack.append(name)
        if len(stack) > x.MAX_DEPTH or name.startswith(x.XI + ' '):
            reject()
        reason_path = [x.SOAP + ' ' + n for n in ('Envelope', 'Body', 'Fault', 'Reason', 'Text')]
        for key in attrs:
            if key.startswith(x.XSI + ' '):
                reject()
            if key.startswith(x.XML + ' ') and not (key == x.XML + ' lang' and stack == reason_path):
                reject()
    p.XmlDeclHandler = declaration
    p.StartElementHandler = start
    p.EndElementHandler = lambda name: stack.pop()
    p.StartDoctypeDeclHandler = reject
    p.ExternalEntityRefHandler = reject
    p.ProcessingInstructionHandler = reject
    p.Parse(data, True)


def check(data, schema, operation, kind, request=None):
    preflight(data)
    root = etree.fromstring(data, x._parser())
    if root.tag != S + 'Envelope':
        raise ValueError('envelope')
    if not schema.validate(root):
        raise ValueError('schema')
    body, = x._only(root, [S + 'Body'])
    if kind == 'ERROR':
        fault, = x._only(body, [S + 'Fault'])
        code, reason, detail = x._only(fault, [S + 'Code', S + 'Reason', S + 'Detail'])
        value, = x._only(code, [S + 'Value'])
        parts = (value.text or '').split(':')
        if len(parts) != 2 or parts[1] not in ('Sender', 'Receiver') or value.nsmap.get(parts[0]) != x.SOAP:
            raise ValueError('fault code')
        text = reason[0] if len(reason) == 1 else None
        if text is None or text.tag != S + 'Text' or set(text.attrib) != {'{' + x.XML + '}lang'} or not text.text:
            raise ValueError('fault reason')
        message, = x._only(detail, [C + 'Message'])
    else:
        message, = x._only(body, [C + 'Message'])
    content, signatures = x._only(message, [C + 'SignedContent', C + 'Signatures'])
    x._check_fields(content, signatures)
    protected = content[0]
    if x._value(protected, 'MessageType') != kind:
        raise ValueError('message type')
    expected = {ACTION + 'RegisterOperation': ('REGISTER_OPERATION', 'REGISTER_OPERATION_RESULT'),
                ACTION + 'GetOperation': ('QUERY_ADMIN_RECORD', 'QUERY_ADMIN_RECORD_RESULT')}
    if operation not in expected or kind not in (*expected[operation], 'ERROR'):
        raise ValueError('action')
    if (kind.endswith('_RESULT') or kind == 'ERROR') and request is None:
        raise ValueError('request required')
    if kind in ('REGISTER_OPERATION', 'QUERY_ADMIN_RECORD') and request is not None:
        raise ValueError('unexpected request')
    if request is not None:
        p = request[0]
        if (x._value(p, 'MessageType') != expected[operation][0]
                or x._value(protected, 'RequestMessageId') != x._value(p, 'MessageId')
                or x._value(protected, 'OperationId') != x._value(p, 'OperationId')
                or x._value(protected, 'InstructionVersion') != x._value(p, 'InstructionVersion')
                or x._value(protected, 'SenderId') != x._value(p, 'RecipientId')
                or x._value(protected, 'RecipientId') != x._value(p, 'SenderId')
                or x._value(protected, 'Environment') != x._value(p, 'Environment')):
            raise ValueError('correlation')
    canonical = etree.tostring(content, method='c14n', exclusive=True, with_comments=False)
    return content, canonical


def main(invalid=False, invalid_wsdl=False):
    if invalid_wsdl:
        parser = etree.XMLParser(load_dtd=False, resolve_entities=False, no_network=True)
        parser.resolvers.add(LocalResolver())
        data = WSDL.read_bytes().replace(b'name="AdministratorPortType"', b'')
        wsdl_structure(data, parser)
    schema, _ = schema_and_client()
    examples = SOAPDIR / 'examples'
    reg, _ = check((examples / 'register-operation.xml').read_bytes(), schema, ACTION + 'RegisterOperation', 'REGISTER_OPERATION')
    query_data = (examples / 'get-operation.xml').read_bytes()
    if invalid:
        query_data = query_data.replace(b'<c:Payload/>', b'<c:Payload/><c:Payload/>')
    query, _ = check(query_data, schema, ACTION + 'GetOperation', 'QUERY_ADMIN_RECORD')
    check((examples / 'register-result.xml').read_bytes(), schema, ACTION + 'RegisterOperation', 'REGISTER_OPERATION_RESULT', reg)
    check((examples / 'get-result.xml').read_bytes(), schema, ACTION + 'GetOperation', 'QUERY_ADMIN_RECORD_RESULT', query)
    check((examples / 'fault.xml').read_bytes(), schema, ACTION + 'GetOperation', 'ERROR', query)
    print('SOAP: WSDL client, local XSD and 5 examples; signatures illustrative')


if __name__ == '__main__':
    cli = argparse.ArgumentParser()
    cli.add_argument('--invalid', action='store_true')
    cli.add_argument('--invalid-wsdl', action='store_true')
    args = cli.parse_args()
    main(args.invalid, args.invalid_wsdl)
