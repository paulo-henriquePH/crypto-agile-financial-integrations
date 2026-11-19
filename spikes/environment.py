"""Inventory only: load the candidate API without signing or handshaking."""
import ctypes as c
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

PREFIX = Path('/opt/cafi-openssl')


def bind(library, name, result, arguments):
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


def inventory():
    crypto_path = PREFIX / 'lib/libcrypto.so.3'
    ssl_path = PREFIX / 'lib/libssl.so.3'
    crypto = c.CDLL(str(crypto_path), mode=c.RTLD_GLOBAL)
    tls = c.CDLL(str(ssl_path))
    version = bind(crypto, 'OpenSSL_version', c.c_char_p, [c.c_int])(0).decode()
    if not version.startswith('OpenSSL 3.5.9 '):
        raise RuntimeError(f'Unexpected OpenSSL: {version}')
    if platform.python_version() != '3.13.11':
        raise RuntimeError('Unexpected Python version')
    fetch = bind(crypto, 'EVP_SIGNATURE_fetch', c.c_void_p,
                 [c.c_void_p, c.c_char_p, c.c_char_p])
    free = bind(crypto, 'EVP_SIGNATURE_free', None, [c.c_void_p])
    signatures = {}
    for name in ('ECDSA', 'ML-DSA-65'):
        pointer = fetch(None, name.encode(), None)
        signatures[name] = bool(pointer)
        if not pointer:
            raise RuntimeError(f'Unavailable signature implementation: {name}')
        free(pointer)
    # Symbol lookup only; API semantics are to be proved in S1-04 through S1-07.
    required = {
        'libcrypto': ['EVP_DigestSignInit_ex', 'EVP_DigestSign',
                      'EVP_DigestVerifyInit_ex', 'EVP_DigestVerify',
                      'EVP_PKEY_CTX_new_from_name', 'EVP_PKEY_generate',
                      'EVP_PKEY_sign_message_init', 'EVP_PKEY_sign',
                      'EVP_PKEY_verify_message_init', 'EVP_PKEY_verify'],
        'libssl': ['TLS_method', 'SSL_CTX_new', 'SSL_CTX_ctrl', 'SSL_ctrl',
                   'SSL_get0_group_name', 'SSL_connect', 'SSL_accept'],
    }
    for library, names in required.items():
        handle = crypto if library == 'libcrypto' else tls
        for name in names:
            getattr(handle, name)
    return {
        'task': 'S1-03', 'kind': 'capability_inventory_not_algorithm_proof',
        'recordedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'codeRevision': os.environ.get('CAFI_CODE_REVISION', 'unspecified'),
        'diagnosticSHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'python': platform.python_version(), 'binding': 'CPython stdlib ctypes',
        'opensslLoaded': version, 'platform': platform.platform(),
        'machine': platform.machine(),
        'compiler': subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0],
        'libraries': {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in (crypto_path, ssl_path)},
        'signatureImplementationsFetched': signatures,
        'symbolsAvailable': required,
        'environment': {name: os.environ.get(name) for name in
                        ('OPENSSL_CONF', 'OPENSSL_MODULES', 'LD_LIBRARY_PATH')},
        'proofsExecuted': [],
        'limitations': ['No signature, verification, key generation or TLS handshake executed.',
                        'ctypes is a low-level candidate binding, not a production adapter.',
                        'TLS negotiated-group observation remains a gate for S1-06/07.'],
    }


if __name__ == '__main__':
    print(json.dumps(inventory(), indent=2))
