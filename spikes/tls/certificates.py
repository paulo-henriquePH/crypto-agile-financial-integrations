"""Temporary laboratory PKI; the OpenSSL CLI only issues certificates."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import subprocess
import tempfile

PREFIX = Path('/opt/cafi-openssl')
OPENSSL = PREFIX / 'bin/openssl'
SERVER_NAME = 'server.cafi.test'
SERVER_CN = 'server-cn.cafi.test'
CLIENT_NAME = 'client.cafi.test'
OTHER_CLIENT_NAME = 'other-client.cafi.test'
COMMAND_TIMEOUT = 5


def issue(directory, *arguments):
    # Suppress CLI output, including diagnostics that could contain material
    # from a temporary file. A timeout/nonzero exit always fails the proof.
    result = subprocess.run([OPENSSL, *arguments], cwd=directory, umask=0o077,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=COMMAND_TIMEOUT)
    if result.returncode:
        raise RuntimeError(f'Certificate issuance ({arguments[0]}) exited {result.returncode}')


def issue_ca(directory, name):
    issue(directory, 'req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt',
          'ec_paramgen_curve:P-256', '-noenc', '-sha256', '-days', '1',
          '-subj', f'/CN={name}', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
          '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
          '-keyout', f'{name}.key', '-out', f'{name}.pem')


def issue_leaf(directory, name, ca, purpose, dns_name, cn):
    issue(directory, 'req', '-new', '-newkey', 'ec', '-pkeyopt',
          'ec_paramgen_curve:P-256', '-noenc', '-sha256', '-subj', f'/CN={cn}',
          '-keyout', f'{name}.key', '-out', f'{name}.csr')
    extensions = directory / f'{name}.ext'
    extensions.write_text(
        'basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature\n'
        f'extendedKeyUsage={purpose}Auth\n'
        f'subjectAltName=DNS:{dns_name}\n',
        encoding='ascii',
    )
    issue(directory, 'x509', '-req', '-in', f'{name}.csr', '-CA', f'{ca}.pem',
          '-CAkey', f'{ca}.key', '-sha256', '-days', '1', '-extfile', extensions.name,
          '-out', f'{name}.pem')


@contextmanager
def lab_certificates():
    # No fallback to the workspace or an alternate temp directory.
    with tempfile.TemporaryDirectory(prefix='cafi-tls-', dir='/tmp') as temporary:
        directory = Path(temporary)
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            raise RuntimeError('Expected mode 0700 on the laboratory PKI directory')
        issue_ca(directory, 'lab-ca')
        issue_ca(directory, 'other-ca')
        issue_leaf(directory, 'server', 'lab-ca', 'server', SERVER_NAME, SERVER_CN)
        issue_leaf(directory, 'untrusted-server', 'other-ca', 'server', SERVER_NAME, SERVER_CN)
        issue_leaf(directory, 'client', 'lab-ca', 'client', CLIENT_NAME, CLIENT_NAME)
        issue_leaf(directory, 'untrusted-client', 'other-ca', 'client', CLIENT_NAME, CLIENT_NAME)
        issue_leaf(directory, 'other-client', 'lab-ca', 'client', OTHER_CLIENT_NAME, CLIENT_NAME)
        for key in directory.glob('*.key'):
            if stat.S_IMODE(key.stat().st_mode) != 0o600:
                raise RuntimeError('Expected mode 0600 on laboratory TLS keys')
        # The trust store never needs a CA private key.
        for ca in ('lab-ca', 'other-ca'):
            os.unlink(directory / f'{ca}.key')
        yield directory
