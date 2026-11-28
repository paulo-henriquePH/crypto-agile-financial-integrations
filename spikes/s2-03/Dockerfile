FROM cafi-soap:s1
COPY requirements.txt /opt/s2-03/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes -r /opt/s2-03/requirements.txt
