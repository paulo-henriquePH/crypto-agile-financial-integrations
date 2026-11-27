"""Direct HTTP/1.1 exchanges, one request per authenticated session."""
import h11

from .security import JSON, SOAP, Route, fields, body, parse, require


def request_headers(route, session, wire):
    return h11.Request(method=route.method, target=route.path, headers=[
        ('Host', session.observation['peerDnsSan']), ('Content-Type', route.media),
        ('Content-Length', str(len(wire)))])


def receive_request(session, boundary, *, lookup=None):
    head, wire = session.link.receive(h11.Request)
    route = Route.from_request(head)
    content, ctx = boundary.receive(wire, route, session, lookup=lookup)
    return route, content, ctx


def send_request(session, boundary, route, template, secret, *, lookup=None):
    wire, ctx = boundary.sign(template, route, secret, session, lookup=lookup)
    session.link.send(request_headers(route, session, wire), wire)
    return ctx


def receive_response(session, boundary, route, request):
    status, content, _ = receive_response_wire(session, boundary, route, request)
    return status, content


def receive_response_wire(session, boundary, route, request):
    """Return original bytes only after all response checks have passed."""
    head, wire = session.link.receive(h11.Response)
    media = SOAP if route.path == '/soap' else JSON
    require([v for k, v in head.headers if k == b'content-type'] == [media.encode()], 'response media')
    content, _ = boundary.receive(wire, route, session, request=request)
    p, payload = ((content['protected'], content['payload']) if media == JSON else
                  (fields(content.find(body.C + 'Protected')), fields(content.find(body.C + 'Payload'))))
    location = response_metadata(request, p, payload, media, head.status_code)
    if location:
        require([v for k, v in head.headers if k == b'location'] == [location.encode()], 'result Location')
    return head.status_code, content, wire


def response_metadata(request, p, payload, media, status):
    if p['messageType'] == 'ERROR':
        if media == JSON:
            require(status in (400, 401, 403, 404, 409, 422, 429, 503), 'REST error status')
            require((payload['code'] == 'NOT_FOUND') == (status == 404), 'absence status')
            require((payload['code'] == 'FORBIDDEN') == (status == 403), 'authorization status')
            if payload['code'] == 'INVALID_SCHEMA':
                require(status == 400, 'schema status')
            if payload['code'] == 'IDEMPOTENCY_CONFLICT':
                require(status == 409, 'conflict status')
        else:
            require(400 <= status < 600, 'SOAP Fault status')
    else:
        statuses = {'CREATE_OPERATION': (201, 200), 'SUBMIT_INSTRUCTION': (202,)}
        require(status in statuses.get(request.action, (200,)), 'result status')
        if request.action == 'CREATE_OPERATION':
            return '/v1/operations/' + p['operationId']


def send_response(session, boundary, route, request, template, secret, status):
    media = SOAP if route.path == '/soap' else JSON
    _, p, payload = parse(template, media == SOAP)
    location = response_metadata(request, p, payload, media, status)
    wire, _ = boundary.sign(template, route, secret, session, request=request)
    headers = [('Content-Type', media), ('Content-Length', str(len(wire)))]
    if location:
        headers.append(('Location', location))
    session.link.send(h11.Response(status_code=status, headers=headers), wire)
    return wire
