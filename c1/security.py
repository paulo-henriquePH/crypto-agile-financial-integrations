"""C1 policy boundary. No deduplication, persistence or financial state here."""
import base64
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import cache
from hashlib import sha256
import json
import re
from threading import Lock, local
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.validators import extend
from lxml import etree
from referencing import Registry, Resource
import rfc8785

from .runtime import ROOT, ECDSA, OpenSSL, body, private_sign, require

JSON = 'application/json'
SOAP = 'application/soap+xml'
ACTION = SOAP + '; action="urn:cafi:administrator:v1:'
# (path template, request media). No normalization of untrusted paths.
ROUTES = {
    'CREATE_OPERATION': ('/v1/operations', JSON),
    'QUERY_OPERATION': ('/v1/operations/{id}/status-queries', JSON),
    'SUBMIT_INSTRUCTION': ('/v1/instructions', JSON),
    'QUERY_INSTRUCTION': ('/v1/instructions/{id}/status-queries', JSON),
    'REGISTER_OPERATION': ('/soap', ACTION + 'RegisterOperation"'),
    'QUERY_ADMIN_RECORD': ('/soap', ACTION + 'GetOperation"'),
}


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    media: str

    @classmethod
    def from_request(cls, head):
        media = [v for k, v in head.headers if k == b'content-type']
        require(len(media) == 1, 'request media')
        return cls(head.method.decode('ascii'), head.target.decode('ascii'), media[0].decode('ascii'))

    @classmethod
    def expected(cls, action, operation):
        path, media = ROUTES[action]
        return cls('POST', path.format(id=operation), media)

    def check(self, action, operation):
        require(self == self.expected(action, operation), 'route/action')


@dataclass(frozen=True)
class Direction:
    sender: str
    recipient: str
    sender_dns: str
    recipient_dns: str
    environment: str
    key_ids: frozenset
    signing_key_id: str
    actions: frozenset  # underlying request types, even on response direction
    scopes: frozenset  # (managerId, portfolioId)


@dataclass(frozen=True)
class Key:
    sender: str
    algorithm: str
    usage: str
    state: str
    start: datetime
    end: datetime
    spki: bytes


def registry(records):
    """Load locally provisioned metadata only. Duplicate identifiers/material fail closed."""
    keys, seen = {}, set()
    for r in records:
        kid = r['keyId']
        require(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', kid) and kid not in keys, 'duplicate/invalid keyId')
        spki = base64.b64decode(r['public'], validate=True)
        key = Key(r['senderId'], r['algorithm'], r['usage'], r['state'],
                  utc(r['notBefore']), utc(r['notAfter']), spki)
        require(key.start < key.end and key.algorithm == ECDSA and key.usage == 'MESSAGE'
                and key.state in ('ACTIVE', 'VERIFY_ONLY', 'REVOKED') and spki not in seen, 'key metadata')
        with OpenSSL().public(ECDSA, spki):
            keys[kid] = key
        seen.add(spki)
    return keys


@dataclass(frozen=True)
class Request:
    action: str
    message: str
    operation: str | None
    sender: str
    recipient: str
    environment: str
    scope: tuple | None
    error_only: str | None = None
    create_digest: bytes | None = None


@dataclass(frozen=True)
class ScopeRef:
    """Selector for an ownership-only read; never a snapshot or cached outcome."""
    action: str
    sender: str
    recipient: str
    operation: str | None
    client_order: str | None  # CREATE_OPERATION only


class Absent(LookupError):
    """Authenticated query of an unknown operation. Only emit a correlated ERROR."""
    def __init__(self, request):
        super().__init__('unknown operation')
        self.request = request


class Forbidden(ValueError):
    """Signature valid; caller may emit a correlated denial, never a snapshot."""
    def __init__(self, reason, request):
        super().__init__(reason)
        self.request = request


class InvalidRoute(ValueError):
    """Authenticated request; only the protected route can correlate an error."""
    def __init__(self, request, protected_route):
        super().__init__('route/action')
        self.request = request
        self.protected_route = protected_route


def utc(value):
    require(re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z', value),
            'UTC timestamp')
    return datetime.fromisoformat(value)


def _soap_integer(checker, value):
    if isinstance(value, Decimal):
        return value.is_finite() and value == value.to_integral_value()
    return Draft202012Validator.TYPE_CHECKER.is_type(value, 'integer')


_SOAPValidator = extend(Draft202012Validator,
                        type_checker=Draft202012Validator.TYPE_CHECKER.redefine('integer', _soap_integer))


def json_validator(*, xml=False):
    files = ['messages/envelope.schema.json', 'schemas/boleta.schema.json', 'schemas/event.schema.json']
    docs = [json.loads((ROOT / 'contracts' / f).read_bytes()) for f in files]
    registry = Registry().with_resources((d['$id'], Resource.from_contents(d)) for d in docs)
    validator = _SOAPValidator if xml else Draft202012Validator
    return validator(docs[0], registry=registry, format_checker=FormatChecker())


_validators = local()
_xml_lock = Lock()


@cache
def _soap_schema():
    # Called only inside _xml_lock, including the first compilation.
    return body.soap_schema(ROOT / 'contracts')


def fields(node):
    """Project an XSD-checked tree; SOAP sequence is exact canonical decimal text."""
    result = {}
    for child in node:
        if not isinstance(child.tag, str):  # comments do not contribute to C14N
            continue
        name = etree.QName(child).localname
        if name == 'Boleta':
            value = fields(child)
        elif name in ('Signers', 'Details'):
            value = [dict(n.attrib) for n in child if isinstance(n.tag, str)]
        else:
            value = body.text(child)
            if name in ('PolicyVersion', 'InstructionVersion'):
                require(value == '1', 'C1 version')
                value = 1
            elif name == 'Sequence':
                require(re.fullmatch(r'[1-9][0-9]*', value), 'XML sequence')
            elif name == 'Retryable':
                value = value in ('true', '1')
        result[name[0].lower() + name[1:]] = value
    return result


def parse(wire, xml):
    if xml:
        # The shared libxml2 validator (including its error log) is never used
        # concurrently. XMLParser and parsed trees remain local to each call.
        with _xml_lock:
            parsed = body.parse_xml(wire, _soap_schema())
    else:
        parsed = body.parse_json(wire)
    require(parsed.profile == 'ECDSA', 'C1 profile')
    if xml:
        node = parsed.content
        p, payload = fields(node.find(body.C + 'Protected')), fields(node.find(body.C + 'Payload'))
        fault = node.getparent().getparent().tag == body.S + 'Detail'
        require(fault == (p['messageType'] == 'ERROR'), 'SOAP Fault/type')
    else:
        p, payload = parsed.content['protected'], parsed.content['payload']
    alg, kid, raw = parsed.signatures[0]
    # Keep the exact digits for business and emission. The logical schema alone
    # sees an exact Decimal integer; constructing it from digits doesn't round.
    schema_payload = {**payload, 'sequence': Decimal(payload['sequence'])} if xml and 'sequence' in payload else payload
    logical = dict(protected=p, payload=schema_payload, signatures=[
        dict(algorithm=alg, keyId=kid, value=base64.b64encode(raw).decode())])
    key = 'soap' if xml else 'json'
    validator = getattr(_validators, key, None)
    if validator is None:
        validator = json_validator(xml=xml)
        setattr(_validators, key, validator)
    require(validator.is_valid(logical), 'envelope schema')
    require(type(p['instructionVersion']) is int and p['instructionVersion'] == 1
            and type(p['policyVersion']) is int and p['policyVersion'] == 1, 'C1 version')
    for field in ('messageId', 'operationId', 'requestMessageId'):
        if field in p:
            require(str(UUID(p[field])) == p[field], 'canonical UUID')
    return parsed, p, payload


class Boundary:
    def __init__(self, direction, keys, *, clock=lambda: datetime.now(UTC)):
        self.policy, self.keys, self.clock = direction, keys, clock
        self.crypto = OpenSSL()

    def key(self, kid, tls_spki, now, signing):
        d = self.policy
        require(kid in d.key_ids and kid in self.keys, 'unauthorized key')
        key = self.keys[kid]
        if signing:
            require(kid == d.signing_key_id, 'wrong emission key')
        require(key.sender == d.sender and key.algorithm == ECDSA and key.usage == 'MESSAGE'
                and key.start <= now <= key.end and
                key.state in (('ACTIVE',) if signing else ('ACTIVE', 'VERIFY_ONLY')), 'inactive key')
        require(tls_spki and tls_spki != key.spki, 'TLS/message key reuse')
        return key

    def receive(self, wire, route, session, *, request=None, lookup=None):
        """Return (signed content, correlation). Call for EVERY attempt before effects/cache."""
        parsed, p, payload = parse(wire, route.path == '/soap')
        self.authenticate(parsed, p, session)
        ctx = self._context(p, payload, route, request, lookup, incoming=True)
        return parsed.content, ctx

    def authenticate(self, parsed, p, session):
        """Verify the channel and signed bytes; this alone does not authorize processing."""
        d = self.policy
        observation = session.observation
        require(observation['peerDnsSan'] == d.sender_dns and observation['verifyCode'] == 0
                and observation['group'].upper() == 'X25519' and observation['protocol'] == 'TLSv1.3'
                and observation['ciphersuite'] == 'TLS_AES_256_GCM_SHA384', 'authenticated link')
        now = self.clock()
        self._direction_time(p, now)
        alg, kid, sig = parsed.signatures[0]
        key = self.key(kid, session.peer_spki, now, False)
        require(self.crypto.verify(alg, key.spki, parsed.canonical, sig), 'invalid signature')

    def _direction_time(self, p, now):
        d = self.policy
        require((p['senderId'], p['recipientId'], p['environment']) ==
                (d.sender, d.recipient, d.environment), 'direction')
        issued, expires = utc(p['issuedAt']), utc(p['expiresAt'])
        require(timedelta() < expires-issued <= timedelta(seconds=120)
                and issued <= now + timedelta(seconds=5) and expires >= now - timedelta(seconds=5), 'validity')

    def _context(self, p, payload, route, request, lookup, *, incoming):
        d = self.policy
        typ, op = p['messageType'], p.get('operationId')
        action = typ if request is None else request.action
        require(action in ROUTES, 'unknown request type')
        expected = Route.expected(action, op if request is None else request.operation)
        if route != expected:
            if incoming and request is None and action in d.actions:
                raise InvalidRoute(Request(action, p['messageId'], op, d.sender, d.recipient,
                                           d.environment, None, error_only='INVALID_SCHEMA'), expected)
            raise ValueError('route/action')
        if request is not None:
            require(action in d.actions or (request.scope is None and typ == 'ERROR'), 'action permission')
            require(typ in ('ERROR', action + '_RESULT') and
                    (d.sender, d.recipient, d.environment) ==
                    (request.recipient, request.sender, request.environment) and
                    p['requestMessageId'] == request.message != p['messageId'] and
                    (request.operation is None or op == request.operation), 'response correlation')
            if typ == 'ERROR':
                require(payload['correlationId'] == request.message, 'error correlation')
                if payload['code'] == 'NOT_FOUND':
                    require(action.startswith('QUERY_') and payload['retryable'] is False, 'absence context')
            elif 'boleta' in payload:
                require((payload['managerId'], payload['boleta']['portfolioId']) == request.scope,
                        'result scope')
                if typ == 'CREATE_OPERATION_RESULT':
                    require(sha256(rfc8785.dumps(payload['boleta'])).digest() == request.create_digest,
                            'creation snapshot differs from request')
            if request.scope is None:
                require(typ == 'ERROR', 'missing query scope')
                if request.error_only:
                    require(payload['code'] == request.error_only, 'unexpected error for authorization context')
            else:
                require(request.scope in d.scopes, 'portfolio permission')
            return request
        base = Request(action, p['messageId'], op, d.sender, d.recipient, d.environment, None)
        denied = replace(base, error_only='FORBIDDEN')
        if action not in d.actions or not d.scopes:
            raise Forbidden('action permission' if action not in d.actions else 'portfolio permission', denied)
        resource = ScopeRef(action, d.sender, d.recipient, op, payload.get('clientOrderId'))
        if typ == 'CREATE_OPERATION':
            scope = (d.sender, payload['portfolioId'])
        elif typ.startswith('QUERY_'):
            require(lookup is not None, 'scope lookup required')
            scope = lookup(resource)
        else:
            scope = (payload['managerId'], payload['boleta']['portfolioId'])
        if scope is None:
            raise Absent(replace(base, error_only='NOT_FOUND') if incoming else base)
        if scope not in d.scopes or (typ == 'QUERY_OPERATION' and scope[0] != d.sender):
            raise Forbidden('portfolio permission', denied)
        if incoming and not typ.startswith('QUERY_'):
            require(lookup is not None, 'scope lookup required')
            stored = lookup(resource)
            if stored is not None and stored != scope and stored not in d.scopes:
                raise Forbidden('stored portfolio permission', denied)
        digest = sha256(rfc8785.dumps(payload)).digest() if typ == 'CREATE_OPERATION' else None
        return replace(base, scope=scope, create_digest=digest)

    def sign(self, template, route, secret, session, *, request=None, lookup=None):
        """Trusted local envelope with placeholder signature ('AA=='); sign approved bytes."""
        require(session.observation['peerDnsSan'] == self.policy.recipient_dns, 'signing destination')
        return self._sign(template, route, secret, session.local_spki, request=request, lookup=lookup)

    def prepare_rest(self, template, route, secret, local_spki):
        """Prepare a REST submit against local policy, without asserting peer authentication."""
        require(route == Route.expected('SUBMIT_INSTRUCTION', None), 'offline route')
        return self._sign(template, route, secret, local_spki)

    def _sign(self, template, route, secret, local_spki, *, request=None, lookup=None):
        xml = route.path == '/soap'
        parsed, p, payload = parse(template, xml)
        now = self.clock()
        self._direction_time(p, now)
        try:
            ctx = self._context(p, payload, route, request, lookup, incoming=False)
        except Absent as absent:
            # Outbound query without local ownership metadata: accept only ERROR.
            ctx = absent.request
        key = self.key(parsed.signatures[0][1], local_spki, now, True)
        sig = base64.b64encode(private_sign(self.crypto, secret, key.spki, parsed.canonical)).decode()
        if xml:
            node = parsed.content
            node.getparent().find(body.C + 'Signatures/' + body.C + 'Signature').text = sig
            wire = etree.tostring(node.getroottree(), encoding='utf-8')
        else:
            alg, kid, _ = parsed.signatures[0]
            wire = json.dumps({**parsed.content, 'signatures': [dict(algorithm=alg, keyId=kid, value=sig)]},
                              ensure_ascii=False, separators=(',', ':')).encode()
        require(len(wire) <= body.MAX_BYTES, 'outbound size')
        return wire, ctx
