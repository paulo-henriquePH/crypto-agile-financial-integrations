FROM cafi-transport:s2-03
COPY deploy/platform/requirements.txt /opt/platform/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes -r /opt/platform/requirements.txt
WORKDIR /repo
COPY c1 c1
COPY services/platform services/platform
COPY contracts contracts
COPY fixtures/boletas fixtures/boletas
COPY spikes/tls/*.py spikes/tls/
COPY spikes/signatures/ecdsa/proof.py spikes/signatures/ecdsa/
COPY spikes/signatures/ml-dsa/proof.py spikes/signatures/ml-dsa/
COPY spikes/s2-02/envelopes.py spikes/s2-02/
COPY spikes/s2-03/transport.py spikes/s2-03/
COPY tests/contracts/signed_crypto.py tests/contracts/
COPY deploy/platform/identity.py deploy/platform/
COPY tests/platform/exchanges.py tests/platform/
