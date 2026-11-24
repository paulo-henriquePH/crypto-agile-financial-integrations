"""Isolated OpenSSL EVP ECDSA proof; not a production binding."""
import ctypes as c
import hashlib
import json
import platform
import sys
from pathlib import Path

LIBRARY = Path('/opt/cafi-openssl/lib/libcrypto.so.3')
PAYLOAD = b'CAFI S1-04: fixed synthetic payload'


def bind(lib, name, result, arguments):
    function = getattr(lib, name)
    function.restype = result
    function.argtypes = arguments
    return function


def run(corrupt_original=False):
    lib = c.CDLL(str(LIBRARY))
    ptr = c.c_void_p
    size = c.c_size_t
    byteptr = c.POINTER(c.c_ubyte)
    version = bind(lib, 'OpenSSL_version', c.c_char_p, [c.c_int])(0).decode()
    if platform.python_version() != '3.13.11' or not version.startswith('OpenSSL 3.5.9 '):
        raise RuntimeError('Unexpected runtime or OpenSSL version')
    ctx_new = bind(lib, 'EVP_PKEY_CTX_new_from_name', ptr, [ptr, c.c_char_p, c.c_char_p])
    ctx_free = bind(lib, 'EVP_PKEY_CTX_free', None, [ptr])
    keygen_init = bind(lib, 'EVP_PKEY_keygen_init', c.c_int, [ptr])
    set_group = bind(lib, 'EVP_PKEY_CTX_set_group_name', c.c_int, [ptr, c.c_char_p])
    generate = bind(lib, 'EVP_PKEY_generate', c.c_int, [ptr, c.POINTER(ptr)])
    key_free = bind(lib, 'EVP_PKEY_free', None, [ptr])
    md_new = bind(lib, 'EVP_MD_CTX_new', ptr, [])
    md_free = bind(lib, 'EVP_MD_CTX_free', None, [ptr])
    sign_init = bind(lib, 'EVP_DigestSignInit_ex', c.c_int,
                     [ptr, ptr, c.c_char_p, ptr, c.c_char_p, ptr, ptr])
    sign = bind(lib, 'EVP_DigestSign', c.c_int, [ptr, byteptr, c.POINTER(size), byteptr, size])
    verify_init = bind(lib, 'EVP_DigestVerifyInit_ex', c.c_int,
                       [ptr, ptr, c.c_char_p, ptr, c.c_char_p, ptr, ptr])
    verify = bind(lib, 'EVP_DigestVerify', c.c_int, [ptr, byteptr, size, byteptr, size])

    def check(value, operation):
        if value != 1:
            raise RuntimeError(f'{operation} failed (OpenSSL return {value})')

    def new_key():
        context = ctx_new(None, b'EC', None)
        if not context:
            raise RuntimeError('EC context allocation failed')
        key = ptr()
        try:
            check(keygen_init(context), 'keygen init')
            check(set_group(context, b'prime256v1'), 'set P-256')
            check(generate(context, c.byref(key)), 'key generation')
            if not key.value:
                raise RuntimeError('key generation returned null')
            return key
        finally:
            ctx_free(context)

    def buffer(data):
        return (c.c_ubyte * len(data)).from_buffer_copy(data)

    def signature(key, message):
        context = md_new()
        if not context:
            raise RuntimeError('digest context allocation failed')
        try:
            check(sign_init(context, None, b'SHA256', None, None, key, None), 'sign init')
            length = size()
            data = buffer(message)
            check(sign(context, None, c.byref(length), data, len(message)), 'signature size')
            output = (c.c_ubyte * length.value)()
            check(sign(context, output, c.byref(length), data, len(message)), 'sign')
            return bytes(output[:length.value])
        finally:
            md_free(context)

    def verified(key, message, sig):
        context = md_new()
        if not context:
            raise RuntimeError('digest context allocation failed')
        try:
            check(verify_init(context, None, b'SHA256', None, None, key, None), 'verify init')
            result = verify(context, buffer(sig), len(sig), buffer(message), len(message))
            if result not in (0, 1):
                raise RuntimeError(f'verification error (OpenSSL return {result})')
            return result == 1
        finally:
            md_free(context)

    keys = []
    try:
        keys.append(new_key())
        keys.append(new_key())
        sig = signature(keys[0], PAYLOAD)
        altered_sig = sig[:-1] + bytes([sig[-1] ^ 1])
        altered_payload = PAYLOAD + b'!'
        cases = {
            'original': verified(keys[0], altered_payload if corrupt_original else PAYLOAD, sig),
            'altered_payload': verified(keys[0], altered_payload, sig),
            'altered_signature': verified(keys[0], PAYLOAD, altered_sig),
            'different_key': verified(keys[1], PAYLOAD, sig),
        }
        expected = {'original': True, 'altered_payload': False,
                    'altered_signature': False, 'different_key': False}
        if cases != expected:
            raise RuntimeError(f'Unexpected verification results: {cases}')
        return {
            'python': platform.python_version(), 'opensslLoaded': version,
            'librarySHA256': hashlib.sha256(LIBRARY.read_bytes()).hexdigest(),
            'proofSHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'algorithm': 'ECDSA P-256 SHA-256', 'signatureEncoding': 'ASN.1 DER',
            'cases': cases,
        }
    finally:
        for key in keys:
            key_free(key)


if __name__ == '__main__':
    if sys.argv[1:] not in ([], ['--corrupt-original']):
        raise SystemExit('usage: proof.py [--corrupt-original]')
    print(json.dumps(run(corrupt_original=bool(sys.argv[1:])), indent=2))
