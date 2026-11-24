"""S1-17 laboratory adapter. Verification imports SPKI public keys only."""

from contextlib import contextmanager
import ctypes as c
import importlib.util
from pathlib import Path
import platform

ROOT = Path(__file__).resolve().parents[2]
ECDSA = 'ECDSA-P256-SHA256'
ML_DSA = 'ML-DSA-65'


def proof(name):
    path = ROOT / 'spikes/signatures' / name / 'proof.py'
    spec = importlib.util.spec_from_file_location(f'_signed_{name}', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ec, ml = proof('ecdsa'), proof('ml-dsa')
LIBRARY = ec.LIBRARY
PTR, INT, SIZE, TEXT = c.c_void_p, c.c_int, c.c_size_t, c.c_char_p
BYTE = c.POINTER(c.c_ubyte)
PARAMS = c.POINTER(ml.OSSLParam)
# OpenSSL 3.5.9 ERR_PACK(lib, 0, reason), from err.h, evperr.h and ecerr.h.
PROVIDER_SIGNATURE_FAILURE = (6 << 23) | 234
EC_BAD_SIGNATURE = (16 << 23) | 156


class OpenSSLError(RuntimeError):
    """Operational failure; never a verdict on an untrusted signature."""

    def __init__(self, operation, result, errors):
        self.result, self.errors = result, errors
        codes = ', '.join(hex(code) for code in errors) or 'empty'
        super().__init__(f'{operation} operational failure (return {result}; OpenSSL queue: {codes})')


class OpenSSL:
    def __init__(self):
        self.lib = c.CDLL(str(LIBRARY))
        self.version = self.bind('OpenSSL_version', TEXT, INT)(0).decode()
        if (platform.python_implementation(), platform.python_version()) != ('CPython', '3.13.11'):
            raise RuntimeError('CPython 3.13.11 required')
        if not self.version.startswith('OpenSSL 3.5.9 '):
            raise RuntimeError('OpenSSL 3.5.9 required')

    def bind(self, name, result, *args):
        return ec.bind(self.lib, name, result, list(args))

    def error_codes(self):
        return tuple(iter(self.bind('ERR_get_error', c.c_ulong), 0))

    @contextmanager
    def owned(self, pointer, free, operation):
        pointer = ml.require_pointer(pointer, operation)
        try:
            yield pointer
        finally:
            self.bind(free, None, PTR)(pointer)

    @staticmethod
    def algorithm(algorithm):
        return {ECDSA: b'EC', ML_DSA: ml.ALGORITHM}[algorithm]

    @contextmanager
    def generate(self, algorithm):
        """Generator only: the EVP_PKEY never leaves process memory."""
        create = self.bind('EVP_PKEY_CTX_new_from_name', PTR, PTR, TEXT, TEXT)
        with self.owned(create(None, self.algorithm(algorithm), ml.PROPERTIES),
                        'EVP_PKEY_CTX_free', 'keygen context') as ctx:
            ml.check(self.bind('EVP_PKEY_keygen_init', INT, PTR)(ctx), 'keygen init')
            if algorithm == ECDSA:
                ml.check(self.bind('EVP_PKEY_CTX_set_group_name', INT, PTR, TEXT)(ctx, b'prime256v1'),
                         'set P-256')
            key = PTR()
            result = self.bind('EVP_PKEY_generate', INT, PTR, c.POINTER(PTR))(ctx, c.byref(key))
            with self.owned(key, 'EVP_PKEY_free', 'key generation') as handle:
                ml.check(result, 'generate key')
                yield handle

    def export_public(self, key):
        encode = self.bind('i2d_PUBKEY', INT, PTR, c.POINTER(BYTE))
        size = encode(key, None)
        if size <= 0:
            raise RuntimeError('SPKI length query failed')
        data = (c.c_ubyte * size)()
        cursor = c.cast(data, BYTE)
        if encode(key, c.byref(cursor)) != size or c.cast(cursor, PTR).value != c.addressof(data) + size:
            raise RuntimeError('SPKI encoding failed')
        return bytes(data)

    @contextmanager
    def public(self, algorithm, der):
        if not 0 < len(der) <= 2048:
            raise ValueError('SPKI length')
        decode = self.bind('d2i_PUBKEY_ex', PTR, c.POINTER(PTR), c.POINTER(BYTE), c.c_long, PTR, TEXT)
        data = ml.buffer(der)
        cursor = c.cast(data, BYTE)
        key = decode(None, c.byref(cursor), len(der), None, ml.PROPERTIES)
        if not key:
            raise OpenSSLError('d2i_PUBKEY_ex (trusted SPKI)', 0, self.error_codes())
        with self.owned(key, 'EVP_PKEY_free', 'public SPKI') as handle:
            if c.cast(cursor, PTR).value != c.addressof(data) + len(der) or self.export_public(handle) != der:
                raise ValueError('noncanonical public SPKI')
            if self.bind('EVP_PKEY_is_a', INT, PTR, TEXT)(handle, self.algorithm(algorithm)) != 1:
                raise ValueError('public key algorithm')
            if algorithm == ECDSA:
                group = c.create_string_buffer(80)
                read = self.bind('EVP_PKEY_get_group_name', INT, PTR, PTR, SIZE, c.POINTER(SIZE))
                result = read(handle, group, len(group), None)
                if result != 1:
                    raise OpenSSLError('EVP_PKEY_get_group_name', result, self.error_codes())
                if group.value != b'prime256v1':
                    raise ValueError('public key curve')
            create = self.bind('EVP_PKEY_CTX_new_from_pkey', PTR, PTR, PTR, TEXT)
            with self.owned(create(None, handle, ml.PROPERTIES),
                            'EVP_PKEY_CTX_free', 'public check context') as ctx:
                result = self.bind('EVP_PKEY_public_check', INT, PTR)(ctx)
                if result != 1:
                    raise OpenSSLError('EVP_PKEY_public_check (trusted SPKI)', result, self.error_codes())
            yield handle

    @contextmanager
    def operation(self, algorithm, key, signing):
        if algorithm == ECDSA:
            op = 'EVP_DigestSign' if signing else 'EVP_DigestVerify'
            with self.owned(self.bind('EVP_MD_CTX_new', PTR)(), 'EVP_MD_CTX_free', 'digest context') as ctx:
                init = self.bind(op + 'Init_ex', INT, PTR, PTR, TEXT, PTR, TEXT, PTR, PARAMS)
                result = init(ctx, None, b'SHA256', None, ml.PROPERTIES, key, None)
                if result != 1:
                    raise OpenSSLError(op + 'Init_ex', result, self.error_codes())
                yield ctx, op
        elif algorithm == ML_DSA:
            op = 'EVP_PKEY_sign' if signing else 'EVP_PKEY_verify'
            create = self.bind('EVP_PKEY_CTX_new_from_pkey', PTR, PTR, PTR, TEXT)
            fetch = self.bind('EVP_SIGNATURE_fetch', PTR, PTR, TEXT, TEXT)
            with (self.owned(create(None, key, ml.PROPERTIES), 'EVP_PKEY_CTX_free', 'message context') as ctx,
                  self.owned(fetch(None, ml.ALGORITHM, ml.PROPERTIES), 'EVP_SIGNATURE_free', 'ML-DSA-65') as sig):
                octets = self.bind('OSSL_PARAM_construct_octet_string', ml.OSSLParam, TEXT, PTR, SIZE)
                integer = self.bind('OSSL_PARAM_construct_int', ml.OSSLParam, TEXT, c.POINTER(INT))
                end = self.bind('OSSL_PARAM_construct_end', ml.OSSLParam)
                empty, encoding, mu = ml.buffer(b'\0'), INT(1), INT(0)
                params = (ml.OSSLParam * 4)(octets(b'context-string', empty, 0),
                                           integer(b'message-encoding', c.byref(encoding)),
                                           integer(b'mu', c.byref(mu)), end())
                init = self.bind(op + '_message_init', INT, PTR, PTR, PARAMS)
                result = init(ctx, sig, params)
                if result != 1:
                    raise OpenSSLError(op + '_message_init', result, self.error_codes())
                yield ctx, op
        else:
            raise ValueError('unsupported algorithm')

    @staticmethod
    def signature_size(algorithm, length):
        return {ECDSA: 8 <= length <= 72, ML_DSA: length == 3309}[algorithm]

    def sign(self, algorithm, key, message):
        with self.operation(algorithm, key, True) as (ctx, op):
            sign = self.bind(op, INT, PTR, BYTE, c.POINTER(SIZE), BYTE, SIZE)
            data, length = ml.buffer(message), SIZE()
            ml.check(sign(ctx, None, c.byref(length), data, len(message)), 'signature length')
            if not self.signature_size(algorithm, length.value):
                raise RuntimeError('unexpected EVP signature capacity')
            out = (c.c_ubyte * length.value)()
            ml.check(sign(ctx, out, c.byref(length), data, len(message)), 'sign')
            if not self.signature_size(algorithm, length.value):
                raise RuntimeError('unexpected EVP signature length')
            return bytes(out[:length.value])

    def _ecdsa_der(self, signature):
        """Confirm ambiguous EVP -1 using the library's strict DER round trip."""
        decode = self.bind('d2i_ECDSA_SIG', PTR, c.POINTER(PTR), c.POINTER(BYTE), c.c_long)
        data = ml.buffer(signature)
        cursor = c.cast(data, BYTE)
        decoded = decode(None, c.byref(cursor), len(signature))
        errors = self.error_codes()
        if not decoded:
            if errors:
                raise OpenSSLError('d2i_ECDSA_SIG', 0, errors)
            return False
        with self.owned(decoded, 'ECDSA_SIG_free', 'ECDSA signature') as handle:
            if errors:
                raise OpenSSLError('d2i_ECDSA_SIG', 1, errors)
            if c.cast(cursor, PTR).value != c.addressof(data) + len(signature):
                return False
            encode = self.bind('i2d_ECDSA_SIG', INT, PTR, c.POINTER(BYTE))
            size = encode(handle, None)
            errors = self.error_codes()
            if size <= 0 or errors:
                raise OpenSSLError('i2d_ECDSA_SIG length', size, errors)
            if size != len(signature):
                return False
            out = (c.c_ubyte * size)()
            cursor = c.cast(out, BYTE)
            result = encode(handle, c.byref(cursor))
            errors = self.error_codes()
            if result != size or c.cast(cursor, PTR).value != c.addressof(out) + size or errors:
                raise OpenSSLError('i2d_ECDSA_SIG', result, errors)
            return bytes(out) == signature

    def verify(self, algorithm, public_der, message, signature):
        if not self.signature_size(algorithm, len(signature)):
            return False
        self.bind('ERR_clear_error', None)()  # isolate this call from prior operations
        with self.public(algorithm, public_der) as key, self.operation(algorithm, key, False) as (ctx, op):
            errors = self.error_codes()
            if errors:
                raise OpenSSLError(op + ' setup', 1, errors)
            verify = self.bind(op, INT, PTR, BYTE, SIZE, BYTE, SIZE)
            result = verify(ctx, ml.buffer(signature), len(signature), ml.buffer(message), len(message))
            errors = self.error_codes()
            if result == 1 and not errors:
                return True
            # 0 is a mismatch; EVP may add a generic provider-failure code.
            mismatch = {PROVIDER_SIGNATURE_FAILURE}
            if algorithm == ECDSA:
                mismatch.add(EC_BAD_SIGNATURE)
            if result == 0 and set(errors) <= mismatch:
                return False
            # The pinned ECDSA provider also uses -1 with an empty queue for
            # malformed/non-canonical DER. Never infer that from -1 alone.
            if result == -1 and algorithm == ECDSA and not errors and not self._ecdsa_der(signature):
                return False
            raise OpenSSLError(op, result, errors)
