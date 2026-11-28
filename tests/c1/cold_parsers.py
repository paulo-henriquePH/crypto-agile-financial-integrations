"""New interpreter: exercise the actual parsers before and during first SOAP use."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from c1.runtime import ROOT, body
from c1.security import parse


def main():
    corpus = ROOT / 'contracts/vectors/signed/corpus'
    data = [(corpus / name).read_bytes() for name in (
        'platform-ecdsa-request.json', 'administrator-ecdsa-request.xml')]
    gate = Barrier(8)

    def exercise(xml):
        gate.wait(timeout=10)
        for _ in range(4):
            _, protected, _ = parse(data[xml], xml)
            if protected['messageType'] != ('REGISTER_OPERATION' if xml else 'CREATE_OPERATION'):
                raise AssertionError('unexpected parsed action')

    with ThreadPoolExecutor(8) as pool, patch.object(body, 'soap_schema', wraps=body.soap_schema) as compile_xsd:
        list(pool.map(exercise, [False] * 8))
        compile_xsd.assert_not_called()
        list(pool.map(exercise, [True] * 8))
        compile_xsd.assert_called_once_with(ROOT / 'contracts')
        list(pool.map(exercise, [False, True] * 4))


if __name__ == '__main__':
    main()
