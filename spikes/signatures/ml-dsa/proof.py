"""Isolated OpenSSL EVP ML-DSA-65 proof; not a production binding."""
import base64
from contextlib import ExitStack
import ctypes as c
import hashlib
import json
from pathlib import Path
import platform
import sys

LIBRARY = Path('/opt/cafi-openssl/lib/libcrypto.so.3')
ALGORITHM = b'ML-DSA-65'
PROPERTIES = b'provider=default'
PAYLOAD = b'CAFI S1-05: fixed synthetic payload\x00with a tail'
CONTEXT = b''


class OSSLParam(c.Structure):
    # Public struct ossl_param_st from <openssl/core.h>.
    _fields_ = [('key', c.c_char_p), ('data_type', c.c_uint), ('data', c.c_void_p),
                ('data_size', c.c_size_t), ('return_size', c.c_size_t)]


def check(value, operation):
    if value != 1:
        raise RuntimeError(f'{operation} failed (OpenSSL return {value})')


def require_pointer(pointer, operation):
    if not pointer:
        raise RuntimeError(f'{operation} returned null')
    return pointer


def buffer(data):
    return (c.c_ubyte * len(data)).from_buffer_copy(data)


def run(corrupt_original=False):
    lib = c.CDLL(str(LIBRARY))
    ptr = c.c_void_p
    size = c.c_size_t
    byteptr = c.POINTER(c.c_ubyte)
    int_ = c.c_int
    text = c.c_char_p

    def bind(name, result, arguments):
        function = getattr(lib, name)
        function.restype = result
        function.argtypes = arguments
        return function

    version = bind('OpenSSL_version', text, [int_])(0).decode()
    python_version = f'{platform.python_implementation()} {platform.python_version()}'
    if python_version != 'CPython 3.13.11' or not version.startswith('OpenSSL 3.5.9 '):
        raise RuntimeError('Unexpected runtime or OpenSSL version')

    ctx_from_name = bind('EVP_PKEY_CTX_new_from_name', ptr, [ptr, text, text])
    ctx_from_key = bind('EVP_PKEY_CTX_new_from_pkey', ptr, [ptr, ptr, text])
    ctx_free = bind('EVP_PKEY_CTX_free', None, [ptr])
    keygen_init = bind('EVP_PKEY_keygen_init', int_, [ptr])
    generate = bind('EVP_PKEY_generate', int_, [ptr, c.POINTER(ptr)])
    key_free = bind('EVP_PKEY_free', None, [ptr])
    public_octets = bind('EVP_PKEY_get_octet_string_param', int_,
                         [ptr, text, byteptr, size, c.POINTER(size)])
    i2d_public = bind('i2d_PUBKEY', int_, [ptr, c.POINTER(byteptr)])
    d2i_public = bind('d2i_PUBKEY', ptr, [c.POINTER(ptr), c.POINTER(byteptr), c.c_long])
    bio_mem = bind('BIO_s_mem', ptr, [])
    bio_new = bind('BIO_new', ptr, [ptr])
    bio_free = bind('BIO_free', int_, [ptr])
    bio_pending = bind('BIO_ctrl_pending', size, [ptr])
    public_pem = bind('PEM_write_bio_PUBKEY', int_, [ptr, ptr])
    fetch = bind('EVP_SIGNATURE_fetch', ptr, [ptr, text, text])
    signature_free = bind('EVP_SIGNATURE_free', None, [ptr])
    signature_provider = bind('EVP_SIGNATURE_get0_provider', ptr, [ptr])
    provider_name = bind('OSSL_PROVIDER_get0_name', text, [ptr])
    octet_param = bind('OSSL_PARAM_construct_octet_string', OSSLParam, [text, ptr, size])
    int_param = bind('OSSL_PARAM_construct_int', OSSLParam, [text, c.POINTER(int_)])
    end_param = bind('OSSL_PARAM_construct_end', OSSLParam, [])
    sign_init = bind('EVP_PKEY_sign_message_init', int_, [ptr, ptr, c.POINTER(OSSLParam)])
    verify_init = bind('EVP_PKEY_verify_message_init', int_, [ptr, ptr, c.POINTER(OSSLParam)])
    sign = bind('EVP_PKEY_sign', int_, [ptr, byteptr, c.POINTER(size), byteptr, size])
    verify = bind('EVP_PKEY_verify', int_, [ptr, byteptr, size, byteptr, size])

    def new_key(owner):
        ctx = require_pointer(ctx_from_name(None, ALGORITHM, PROPERTIES), 'keygen context')
        key = ptr()
        try:
            check(keygen_init(ctx), 'keygen init')
            result = generate(ctx, c.byref(key))
            if key:
                owner.callback(key_free, key)
            check(result, 'key generation')
            return require_pointer(key, 'key generation')
        finally:
            ctx_free(ctx)

    def public_only(key, owner):
        # Serialize only the public component into DER and parse a separate verifier key.
        length = i2d_public(key, None)
        if length <= 0:
            raise RuntimeError('SPKI DER size query failed')
        data = (c.c_ubyte * length)()
        cursor = c.cast(data, byteptr)
        if i2d_public(key, c.byref(cursor)) != length:
            raise RuntimeError('SPKI DER public encoding failed')
        cursor = c.cast(data, byteptr)
        public = require_pointer(d2i_public(None, c.byref(cursor), length), 'SPKI DER public decoding')
        owner.callback(key_free, public)
        if c.cast(cursor, ptr).value != c.addressof(data) + length:
            raise RuntimeError('Unconsumed data after SPKI DER decoding')
        return public, length

    def raw_public(key):
        length = size()
        check(public_octets(key, b'pub', None, 0, c.byref(length)), 'raw public key size')
        data = (c.c_ubyte * length.value)()
        check(public_octets(key, b'pub', data, len(data), c.byref(length)), 'raw public key')
        return bytes(data[:length.value])

    def public_pem_size(key):
        bio = require_pointer(bio_new(bio_mem()), 'public PEM memory BIO')
        try:
            check(public_pem(bio, key), 'SPKI PEM public encoding')
            return bio_pending(bio)
        finally:
            bio_free(bio)

    def init_message(init, ctx, signature, context):
        # Use explicit public-API parameters: no ExternalMu, no disabled framing.
        context_data = buffer(context or b'\x00')  # non-null storage even for length zero
        encoding, mu = int_(1), int_(0)
        params = (OSSLParam * 4)(
            octet_param(b'context-string', context_data, len(context)),
            int_param(b'message-encoding', c.byref(encoding)),
            int_param(b'mu', c.byref(mu)),
            end_param(),
        )
        check(init(ctx, signature, params), 'message init')

    def sign_message(key, signature, message):
        ctx = require_pointer(ctx_from_key(None, key, PROPERTIES), 'sign context')
        try:
            init_message(sign_init, ctx, signature, CONTEXT)
            data = buffer(message)
            length = size()
            check(sign(ctx, None, c.byref(length), data, len(message)), 'signature size')
            output = (c.c_ubyte * length.value)()
            check(sign(ctx, output, c.byref(length), data, len(message)), 'sign')
            return bytes(output[:length.value])
        finally:
            ctx_free(ctx)

    def verified(key, signature, message, sig, context=CONTEXT):
        ctx = require_pointer(ctx_from_key(None, key, PROPERTIES), 'verify context')
        try:
            init_message(verify_init, ctx, signature, context)
            result = verify(ctx, buffer(sig), len(sig), buffer(message), len(message))
            if result not in (0, 1):
                raise RuntimeError(f'verification error (OpenSSL return {result})')
            return result == 1
        finally:
            ctx_free(ctx)

    with ExitStack() as owner:
        signature = require_pointer(fetch(None, ALGORITHM, PROPERTIES), 'ML-DSA-65 signature fetch')
        owner.callback(signature_free, signature)
        provider = require_pointer(signature_provider(signature), 'signature provider')
        provider_loaded = provider_name(provider).decode()
        signing_key = new_key(owner)
        public_key, der_size = public_only(signing_key, owner)
        different_key, _ = public_only(new_key(owner), owner)
        raw = raw_public(public_key)
        if raw == raw_public(different_key):
            raise RuntimeError('Expected distinct public keys')
        sig = sign_message(signing_key, signature, PAYLOAD)
        # Flip a bit after the embedded NUL in the message, and in the
        # signature challenge (not in its length or hint encoding).
        altered_payload = PAYLOAD[:-1] + bytes([PAYLOAD[-1] ^ 1])
        altered_sig = bytes([sig[0] ^ 1]) + sig[1:]
        cases = {
            'original': verified(public_key, signature,
                                 altered_payload if corrupt_original else PAYLOAD, sig),
            'altered_payload': verified(public_key, signature, altered_payload, sig),
            'altered_signature': verified(public_key, signature, PAYLOAD, altered_sig),
            'different_key': verified(different_key, signature, PAYLOAD, sig),
            'different_context': verified(public_key, signature, PAYLOAD, sig, b'non-empty'),
        }
        expected = {'original': True, 'altered_payload': False, 'altered_signature': False,
                    'different_key': False, 'different_context': False}
        if cases != expected:
            raise RuntimeError(f'Unexpected verification results: {cases}')

        sizes = {
            'signatureRawBytes': len(sig),
            'signatureBase64Chars': len(base64.b64encode(sig)),
            'publicKeyRawBytes': len(raw),
            'publicKeySpkiDerBytes': der_size,
            'publicKeySpkiPemBytes': public_pem_size(public_key),
        }
        # FIPS 204 Table 2 (raw), RFC 4648 (Base64), RFC 9881 (SPKI),
        # RFC 7468 (PEM with 64-character lines and LF as emitted by OpenSSL).
        expected_sizes = {'signatureRawBytes': 3309, 'signatureBase64Chars': 4412,
                          'publicKeyRawBytes': 1952, 'publicKeySpkiDerBytes': 1974,
                          'publicKeySpkiPemBytes': 2726}
        if sizes != expected_sizes:
            raise RuntimeError(f'Unexpected ML-DSA-65 sizes: {sizes}')
        return {
            'runtime': python_version, 'opensslLoaded': version, 'provider': provider_loaded,
            'librarySHA256': hashlib.sha256(LIBRARY.read_bytes()).hexdigest(),
            'proofSHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'algorithm': ALGORITHM.decode(), 'mode': 'pure', 'contextBytes': len(CONTEXT),
            'payloadBytes': len(PAYLOAD), 'sizes': sizes, 'cases': cases,
        }


if __name__ == '__main__':
    if sys.argv[1:] not in ([], ['--corrupt-original']):
        raise SystemExit('usage: proof.py [--corrupt-original]')
    print(json.dumps(run(corrupt_original=bool(sys.argv[1:])), indent=2))
