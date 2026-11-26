"""Isolated TLS 1.3 mTLS over loopback via CPython ctypes and OpenSSL."""
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import platform
from select import select
import socket
from time import monotonic

if __package__:
    from .certificates import CLIENT_NAME, PREFIX, SERVER_CN, SERVER_NAME, lab_certificates
else:
    from certificates import CLIENT_NAME, PREFIX, SERVER_CN, SERVER_NAME, lab_certificates

LIBCRYPTO = PREFIX / 'lib/libcrypto.so.3'
LIBSSL = PREFIX / 'lib/libssl.so.3'
X25519, HYBRID = b'X25519', b'X25519MLKEM768'
CIPHER = b'TLS_AES_256_GCM_SHA384'
SIGALG = b'ecdsa_secp256r1_sha256'
TIMEOUT = 5
ACK = b'\x01'

# Public constants/macros in the pinned OpenSSL headers (ssl.h, prov_ssl.h,
# x509v3.h, x509_vfy.h). SSL_CTX_* macro calls use their SSL_CTX_ctrl equivalents.
TLS1_3_VERSION = 0x0304
SET_MIN_PROTO_VERSION, GET_MIN_PROTO_VERSION = 123, 130
SET_MAX_PROTO_VERSION, GET_MAX_PROTO_VERSION = 124, 131
SET_GROUPS_LIST, SET_SIGALGS_LIST, SET_CLIENT_SIGALGS_LIST = 92, 98, 102
SET_SESS_CACHE_MODE, GET_SESS_CACHE_MODE = 44, 45
SSL_SESS_CACHE_OFF = 0
SSL_OP_NO_TICKET = 1 << 14
SSL_FILETYPE_PEM = 1
SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 1, 2
X509_CHECK_FLAG_NO_WILDCARDS, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = 0x2, 0x20
SSL_ERROR_SSL, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE = 1, 2, 3
SSL_EARLY_DATA_NOT_SENT, X509_V_OK = 0, 0
X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, X509_V_ERR_HOSTNAME_MISMATCH = 20, 62


def require(condition, stage):
    if not condition:
        raise RuntimeError(stage)


def checked(value, stage):
    require(value == 1, f'{stage}: OpenSSL return {value}')


def text(value, stage):
    require(value, f'{stage}: OpenSSL did not return a name')
    return value.decode('ascii')


class OpenSSL:
    def __init__(self):
        crypto = c.CDLL(str(LIBCRYPTO))
        ssl = c.CDLL(str(LIBSSL))
        p, s, i, u, n = c.c_void_p, c.c_char_p, c.c_int, c.c_uint32, c.c_size_t
        l, ul, u64 = c.c_long, c.c_ulong, c.c_uint64

        def bind(library, signatures):
            for name, result, *arguments in signatures:
                function = getattr(library, name)
                function.restype = result
                function.argtypes = arguments
                setattr(self, name, function)

        bind(crypto, [
            ('OpenSSL_version', s, i),
            ('ERR_clear_error', None), ('ERR_peek_last_error', ul),
            ('ERR_reason_error_string', s, ul),
            ('OPENSSL_sk_num', i, p), ('X509_verify_cert_error_string', s, l),
            ('X509_get0_pubkey', p, p), ('X509_get_signature_nid', i, p),
            ('OBJ_nid2sn', s, i), ('EVP_PKEY_get0_type_name', s, p),
            ('EVP_PKEY_get_group_name', i, p, p, n, c.POINTER(n)),
        ])
        require(c.cast(ssl.OpenSSL_version, p).value == c.cast(self.OpenSSL_version, p).value,
                'libssl must resolve the pinned libcrypto')
        self.version = text(self.OpenSSL_version(0), 'OpenSSL version')
        self.runtime = f'{platform.python_implementation()} {platform.python_version()}'
        require(self.runtime == 'CPython 3.13.11' and self.version.startswith('OpenSSL 3.5.9 '),
                'Unexpected runtime or loaded OpenSSL')

        bind(ssl, [
            ('TLS_method', p), ('SSL_CTX_new', p, p), ('SSL_CTX_free', None, p),
            ('SSL_CTX_ctrl', l, p, i, l, p),
            ('SSL_CTX_set_ciphersuites', i, p, s),
            ('SSL_CTX_set_verify', None, p, i, p), ('SSL_CTX_get_verify_mode', i, p),
            ('SSL_CTX_load_verify_locations', i, p, s, s),
            ('SSL_CTX_use_certificate_chain_file', i, p, s),
            ('SSL_CTX_use_PrivateKey_file', i, p, s, i), ('SSL_CTX_check_private_key', i, p),
            ('SSL_CTX_set_options', u64, p, u64), ('SSL_CTX_get_options', u64, p),
            ('SSL_CTX_set_num_tickets', i, p, n), ('SSL_CTX_get_num_tickets', n, p),
            ('SSL_CTX_set_max_early_data', i, p, u), ('SSL_CTX_get_max_early_data', u, p),
            ('SSL_CTX_set_recv_max_early_data', i, p, u), ('SSL_CTX_get_recv_max_early_data', u, p),
            ('SSL_new', p, p), ('SSL_free', None, p), ('SSL_set_fd', i, p, i),
            ('SSL_set_hostflags', None, p, c.c_uint), ('SSL_set1_host', i, p, s),
            ('SSL_connect', i, p), ('SSL_accept', i, p), ('SSL_get_error', i, p, i),
            ('SSL_write_ex', i, p, p, n, c.POINTER(n)),
            ('SSL_read_ex', i, p, p, n, c.POINTER(n)),
            ('SSL_is_init_finished', i, p), ('SSL_get_version', s, p),
            ('SSL_get0_group_name', s, p), ('SSL_get_current_cipher', p, p),
            ('SSL_CIPHER_get_name', s, p), ('SSL_get_verify_result', l, p),
            ('SSL_get0_peer_certificate', p, p), ('SSL_get_certificate', p, p), ('SSL_get0_peername', s, p),
            ('SSL_get0_verified_chain', p, p),
            ('SSL_session_reused', i, p), ('SSL_get_session', p, p),
            ('SSL_SESSION_has_ticket', i, p), ('SSL_SESSION_is_resumable', i, p),
            ('SSL_get_early_data_status', i, p),
        ])

    @contextmanager
    def context(self, directory, certificate, *, server, group):
        method = self.TLS_method()
        require(method, 'TLS_method returned NULL')
        ctx = self.SSL_CTX_new(method)
        require(ctx, 'SSL_CTX_new returned NULL')
        try:
            for command in (SET_MIN_PROTO_VERSION, SET_MAX_PROTO_VERSION):
                checked(self.SSL_CTX_ctrl(ctx, command, TLS1_3_VERSION, None), 'set TLS version')
            for command, value in ((SET_GROUPS_LIST, group), (SET_SIGALGS_LIST, SIGALG),
                                   (SET_CLIENT_SIGALGS_LIST, SIGALG)):
                checked(self.SSL_CTX_ctrl(ctx, command, 0, c.c_char_p(value)), 'set TLS algorithm list')
            checked(self.SSL_CTX_set_ciphersuites(ctx, CIPHER), 'set TLS 1.3 ciphersuite')
            verify = SSL_VERIFY_PEER | (SSL_VERIFY_FAIL_IF_NO_PEER_CERT if server else 0)
            self.SSL_CTX_set_verify(ctx, verify, None)  # Default callback enforces X.509 validation.
            checked(self.SSL_CTX_load_verify_locations(ctx, os.fsencode(directory / 'lab-ca.pem'),
                                                      None), 'load only the laboratory trust anchor')
            if certificate is not None:
                checked(self.SSL_CTX_use_certificate_chain_file(
                    ctx, os.fsencode(directory / f'{certificate}.pem')), 'load TLS certificate')
                checked(self.SSL_CTX_use_PrivateKey_file(
                    ctx, os.fsencode(directory / f'{certificate}.key'), SSL_FILETYPE_PEM),
                    'load TLS PEM key')
                checked(self.SSL_CTX_check_private_key(ctx), 'match TLS certificate and key')

            self.SSL_CTX_ctrl(ctx, SET_SESS_CACHE_MODE, SSL_SESS_CACHE_OFF, None)
            self.SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET)
            checked(self.SSL_CTX_set_num_tickets(ctx, 0), 'disable TLS 1.3 ticket issuance')
            checked(self.SSL_CTX_set_max_early_data(ctx, 0), 'disable early data')
            checked(self.SSL_CTX_set_recv_max_early_data(ctx, 0), 'disable receipt of early data')
            for command in (GET_MIN_PROTO_VERSION, GET_MAX_PROTO_VERSION):
                require(self.SSL_CTX_ctrl(ctx, command, 0, None) == TLS1_3_VERSION,
                        'Unexpected TLS version bound')
            require(self.SSL_CTX_get_verify_mode(ctx) == verify, 'Unexpected peer verification mode')
            controls = {
                'cacheMode': self.SSL_CTX_ctrl(ctx, GET_SESS_CACHE_MODE, 0, None),
                'noTicketOption': bool(self.SSL_CTX_get_options(ctx) & SSL_OP_NO_TICKET),
                'numTickets': self.SSL_CTX_get_num_tickets(ctx),
                'maxEarlyData': self.SSL_CTX_get_max_early_data(ctx),
                'recvMaxEarlyData': self.SSL_CTX_get_recv_max_early_data(ctx),
            }
            require(controls == {'cacheMode': SSL_SESS_CACHE_OFF, 'noTicketOption': True,
                                 'numTickets': 0, 'maxEarlyData': 0, 'recvMaxEarlyData': 0},
                    'Unexpected resumption/early-data controls')
            yield ctx, controls
        finally:
            self.SSL_CTX_free(ctx)

    @contextmanager
    def connection(self, ctx, sock, peer_name):
        ssl = self.SSL_new(ctx)
        require(ssl, 'SSL_new returned NULL')
        try:
            sock.setblocking(False)
            checked(self.SSL_set_fd(ssl, sock.fileno()), 'SSL_set_fd')
            self.SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_WILDCARDS |
                                   X509_CHECK_FLAG_NEVER_CHECK_SUBJECT)
            checked(self.SSL_set1_host(ssl, peer_name.encode('ascii')), 'set expected peer DNS SAN')
            yield ssl
        finally:
            self.SSL_free(ssl)

    def io(self, operation, ssl, sock, deadline, *args):
        while (remaining := deadline - monotonic()) > 0:
            self.ERR_clear_error()
            result = operation(ssl, *args)
            if result == 1:
                return {'return': result}
            # Same thread, no intervening OpenSSL call after the failed operation.
            error = self.SSL_get_error(ssl, result)
            if error not in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                reason = self.ERR_reason_error_string(self.ERR_peek_last_error())
                code = self.SSL_get_verify_result(ssl)
                return {'return': result, 'sslError': error,
                        'reason': reason.decode('ascii') if reason else None,
                        'verifyCode': code,
                        'verifyReason': text(self.X509_verify_cert_error_string(code), 'verify reason')}
            readable, writable, _ = select([sock] if error == SSL_ERROR_WANT_READ else [],
                                           [sock] if error == SSL_ERROR_WANT_WRITE else [],
                                           [], remaining)
            if not (readable or writable):
                break
        raise TimeoutError(f'{operation.__name__} exceeded the per-connection I/O deadline')

    def observed(self, ssl, expected_group, peer_name):
        require(self.SSL_is_init_finished(ssl) == 1, 'TLS handshake not finished')
        verify = self.SSL_get_verify_result(ssl)
        cert = self.SSL_get0_peer_certificate(ssl)
        chain = self.SSL_get0_verified_chain(ssl)
        require(verify == X509_V_OK and cert and chain, 'Missing verified peer certificate/chain')
        chain_length = self.OPENSSL_sk_num(chain)
        require(chain_length == 2, 'Expected verified leaf and laboratory trust anchor')
        peer = text(self.SSL_get0_peername(ssl), 'verified DNS SAN')
        require(peer == peer_name, 'Unexpected verified peer DNS SAN')
        public_key = self.X509_get0_pubkey(cert)
        require(public_key, 'Missing peer public key')
        key_type = text(self.EVP_PKEY_get0_type_name(public_key), 'peer key type')
        curve = c.create_string_buffer(64)
        checked(self.EVP_PKEY_get_group_name(public_key, curve, len(curve), None), 'peer key curve')
        signature = text(self.OBJ_nid2sn(self.X509_get_signature_nid(cert)), 'certificate signature')
        require(key_type == 'EC' and curve.value in (b'prime256v1', b'P-256')
                and signature == 'ecdsa-with-SHA256', 'Unexpected traditional peer certificate profile')
        protocol = text(self.SSL_get_version(ssl), 'negotiated TLS version')
        group = text(self.SSL_get0_group_name(ssl), 'negotiated TLS group')
        cipher = self.SSL_get_current_cipher(ssl)
        require(cipher, 'Missing negotiated cipher')
        suite = text(self.SSL_CIPHER_get_name(cipher), 'negotiated ciphersuite')
        # Compare case-insensitively but retain the spelling reported by OpenSSL.
        require((protocol, group.casefold(), suite)
                == ('TLSv1.3', expected_group.decode().casefold(), CIPHER.decode()),
                f'Unexpected negotiated protocol/group/suite: {protocol}/{group}/{suite}')
        session = self.SSL_get_session(ssl)
        require(session, 'Missing TLS session')
        resumption = (self.SSL_session_reused(ssl), self.SSL_SESSION_has_ticket(session),
                      self.SSL_SESSION_is_resumable(session))
        early_data = self.SSL_get_early_data_status(ssl)
        require(resumption == (0, 0, 0) and early_data == SSL_EARLY_DATA_NOT_SENT,
                'Unexpected resumption, session ticket, or early data')
        return {
            'protocol': protocol, 'group': group, 'ciphersuite': suite,
            'peerDnsSan': peer, 'verifyCode': verify, 'verifiedChainLength': chain_length,
            'peerKeyType': key_type, 'peerKeyCurve': curve.value.decode('ascii'),
            'peerCertificateSignature': signature, 'sessionReused': bool(resumption[0]),
            'sessionHasTicket': bool(resumption[1]), 'sessionResumable': bool(resumption[2]),
            'earlyDataStatus': 'SSL_EARLY_DATA_NOT_SENT',
        }


def exchange(api, client_ctx, server_ctx, *, client_group, server_group, server_name):
    with ExitStack() as owner:
        listener = owner.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        listener.settimeout(TIMEOUT)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        client_socket = owner.enter_context(socket.create_connection(listener.getsockname(), TIMEOUT))
        server_socket = owner.enter_context(listener.accept()[0])
        client = owner.enter_context(api.connection(client_ctx, client_socket, server_name))
        server = owner.enter_context(api.connection(server_ctx, server_socket, CLIENT_NAME))
        deadline = monotonic() + TIMEOUT
        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(api.io, api.SSL_accept, server, server_socket, deadline)
            client_result = api.io(api.SSL_connect, client, client_socket, deadline)
            server_result = pending.result()

        result = {'clientHandshake': client_result, 'serverHandshake': server_result}
        if server_result['return'] == 1 and client_result['return'] == 1:
            client_observed = api.observed(client, client_group, server_name)
            server_observed = api.observed(server, server_group, CLIENT_NAME)
            count = c.c_size_t()
            sent = api.io(api.SSL_write_ex, server, server_socket, deadline,
                          c.create_string_buffer(ACK), len(ACK), c.byref(count))
            require(sent['return'] == 1 and count.value == len(ACK), 'TLS acknowledgment write failed')
            received = c.create_string_buffer(len(ACK))
            read = api.io(api.SSL_read_ex, client, client_socket, deadline,
                          received, len(ACK), c.byref(count))
            require(read['return'] == 1 and count.value == len(ACK) and received.raw == ACK,
                    'TLS acknowledgment not received')
            # Observe again after SSL_read_ex, which can process post-handshake tickets.
            require(api.observed(client, client_group, server_name) == client_observed
                    and api.observed(server, server_group, CLIENT_NAME) == server_observed,
                    'TLS observations changed after the acknowledgment')
            return {**result, 'accepted': True, 'acknowledged': True,
                    'client': client_observed, 'server': server_observed}

        if client_result['return'] == 1:
            # TLS 1.3 clients can finish locally before the server processes
            # client authentication. Read the server's alert, not application data.
            alert = api.io(api.SSL_read_ex, client, client_socket, deadline,
                           c.create_string_buffer(1), 1, c.byref(c.c_size_t()))
            require(alert['return'] != 1 and alert['sslError'] == SSL_ERROR_SSL,
                    f'Expected fatal TLS alert at client: {alert}')
            result['clientReadAfterConnect'] = alert
        return {**result, 'accepted': False, 'acknowledged': False}


def run(wrong_positive_name=False, *, hybrid=False):
    api = OpenSSL()
    group = HYBRID if hybrid else X25519
    cases = {}

    def connect(client, server, name=SERVER_NAME, *, client_group=group):
        return exchange(api, client, server, client_group=client_group,
                        server_group=group, server_name=name)

    def reject(case, result, side, reason, verify_code):
        failure = result[f'{side}Handshake']
        require(not result['accepted'] and not result['acknowledged'] and failure['return'] != 1
                and failure['sslError'] == SSL_ERROR_SSL and failure['reason'] == reason
                and failure['verifyCode'] == verify_code, f'Unexpected {case} result: {result}')
        cases[case] = {**result, 'rejectedBy': side}

    with lab_certificates() as pki:
        with api.context(pki, 'client', server=False, group=group) as (client, client_controls), \
                api.context(pki, 'server', server=True, group=group) as (server, server_controls):
            for case in ('trusted_peers', 'trusted_peers_second_connection'):
                result = connect(client, server, SERVER_CN if wrong_positive_name else SERVER_NAME)
                require(result['accepted'], f'{case} did not pass: {result}')
                cases[case] = result
            reject('wrong_server_name', connect(client, server, SERVER_CN), 'client',
                   'certificate verify failed', X509_V_ERR_HOSTNAME_MISMATCH)
            with api.context(pki, 'untrusted-server', server=True, group=group) as (bad_server, _):
                reject('untrusted_server', connect(client, bad_server), 'client',
                       'certificate verify failed', X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            for case, certificate, reason, verify_code in (
                ('untrusted_client', 'untrusted-client', 'certificate verify failed',
                 X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
                ('missing_client_certificate', None, 'peer did not return a certificate', X509_V_OK),
                ('wrong_client_name', 'other-client', 'certificate verify failed',
                 X509_V_ERR_HOSTNAME_MISMATCH),
            ):
                with api.context(pki, certificate, server=False, group=group) as (bad_client, _):
                    reject(case, connect(bad_client, server), 'server', reason, verify_code)

            if hybrid:
                # Same trusted identities and hybrid server; change only the client's group.
                with api.context(pki, 'client', server=False, group=X25519) as (classic_client, _):
                    result = connect(classic_client, server, client_group=X25519)
                case = 'x25519_client_to_hybrid_only_server'
                reject(case, result, 'server', 'no suitable key share', X509_V_OK)
                failure = result['clientHandshake']
                require(failure['return'] < 0 and failure['sslError'] == SSL_ERROR_SSL,
                        f'Expected fatal TLS handshake failure at client: {result}')
                cases[case].update(clientGroup=X25519.decode(), serverGroup=group.decode())

    files = (LIBCRYPTO, LIBSSL, Path(__file__), Path(__file__).with_name('certificates.py'))
    return {
        'runtime': api.runtime, 'binding': 'CPython stdlib ctypes', 'opensslLoaded': api.version,
        'machine': platform.machine(),
        'sha256': {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
        'policy': {'group': group.decode(), 'protocol': 'TLSv1.3', 'ciphersuite': CIPHER.decode(),
                   'signatureAlgorithm': SIGALG.decode(), 'clientContext': client_controls,
                   'serverContext': server_controls},
        'cases': cases,
    }


if __name__ == '__main__':
    parser = ArgumentParser(allow_abbrev=False)
    parser.add_argument('--hybrid', action='store_true', help='require X25519MLKEM768 instead of X25519')
    parser.add_argument('--wrong-positive-name', action='store_true', help='force the positive case to fail')
    print(json.dumps(run(**vars(parser.parse_args())), indent=2))
