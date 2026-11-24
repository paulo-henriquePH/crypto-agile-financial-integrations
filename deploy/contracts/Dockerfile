FROM cafi-spikes:s1
COPY deploy/contracts/requirements-boleta.txt /tmp/requirements-boleta.txt
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-boleta.txt
COPY contracts/vectors/json/requirements.txt /tmp/requirements-jcs.txt
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-jcs.txt
