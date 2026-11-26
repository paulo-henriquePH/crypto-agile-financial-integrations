"""Compose the exact approved libraries; repository root on PYTHONPATH."""
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
import os
import stat

from spikes.tls import proof as tls
from tests.contracts.signed_crypto import ECDSA, OpenSSL, PTR, INT, TEXT

body = import_module('spikes.s2-02.envelopes')
http = import_module('spikes.s2-03.transport')
ROOT = Path(__file__).resolve().parents[1]
require = body.require


@dataclass(frozen=True)
class Session:
    link: object
    observation: dict
    peer_spki: bytes
    local_spki: bytes


@contextmanager
def connect(directory, certificate, socket, *, server, peer_dns):
    """Wrap an accepted/connected socket; certificate and peer_dns are local config."""
    api = tls.OpenSSL()
    with api.context(directory, certificate, server=server, group=tls.X25519) as (ctx, _):
        with http.channel(api, ctx, socket, server=server, group=tls.X25519,
                          peer=peer_dns, limit=body.MAX_BYTES) as (link, observation):
            cert = api.SSL_get0_peer_certificate(link.ssl)
            crypto = OpenSSL()
            local_cert = api.SSL_get_certificate(link.ssl)
            require(local_cert, 'local certificate')
            yield Session(link, observation, crypto.export_public(api.X509_get0_pubkey(cert)),
                          crypto.export_public(api.X509_get0_pubkey(local_cert)))


def private_sign(crypto, secret, expected_spki, canonical):
    """Unencrypted PEM in a private, read-only secret mount; validate before use."""
    with Path(secret).open('rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077, 'secret permissions')
        pem = stream.read(4097)
    require(len(pem) <= 4096 and pem.startswith(b'-----BEGIN PRIVATE KEY-----'), 'PKCS8 PEM')
    with crypto.owned(crypto.bind('BIO_new_mem_buf', PTR, TEXT, INT)(pem, len(pem)),
                      'BIO_free', 'secret buffer') as bio:
        load = crypto.bind('PEM_read_bio_PrivateKey', PTR, PTR, PTR, PTR, PTR)
        with crypto.owned(load(bio, None, None, None), 'EVP_PKEY_free', 'message key') as key:
            require(crypto.export_public(key) == expected_spki, 'wrong signing secret')
            with crypto.public(ECDSA, expected_spki):
                return crypto.sign(ECDSA, key, canonical)
