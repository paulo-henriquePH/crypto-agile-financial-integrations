FROM cafi-spikes:s1 AS jcs
COPY deploy/contracts/requirements-boleta.txt /tmp/requirements-boleta.txt
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-boleta.txt
COPY contracts/vectors/json/requirements.txt /tmp/requirements-jcs.txt
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-jcs.txt

FROM jcs AS xml
COPY deploy/contracts/requirements-xml.txt /tmp/requirements-xml.txt
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-xml.txt

FROM xml AS openapi
COPY deploy/contracts/requirements-openapi.txt /tmp/requirements-openapi.txt
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-openapi.txt

FROM openapi AS soap
COPY deploy/contracts/requirements-soap.txt /tmp/requirements-soap.txt
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-soap.txt

# Mantém o build sem --target equivalente ao ambiente S1-12-C1.
FROM jcs AS contracts
