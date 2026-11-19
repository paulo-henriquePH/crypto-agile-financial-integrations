FROM python:3.13.11-bookworm@sha256:b3ad23176613a34fcd715a28da314a0cbbd230dcc68798efb80ec30292b2a683

# Toolchain and OS packages are pinned transitively by the base image digest.
# No apt upgrade/install, floating pip dependency or host OpenSSL is used.
ARG OPENSSL_VERSION=3.5.9
ARG OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
RUN mkdir -p /tmp/cafi-build && cd /tmp/cafi-build \
    && curl --fail --location --retry 3 -o openssl.tar.gz \
       https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
    && echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum --check --strict \
    && tar -xzf openssl.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure --prefix=/opt/cafi-openssl --libdir=lib shared no-tests \
    && make -j2 \
    && make install_sw \
    && rm -rf /tmp/cafi-build

ENV LD_LIBRARY_PATH=/opt/cafi-openssl/lib \
    OPENSSL_MODULES=/opt/cafi-openssl/lib/ossl-modules \
    OPENSSL_CONF=/opt/cafi-openssl/ssl/openssl.cnf \
    PYTHONDONTWRITEBYTECODE=1
RUN mkdir -p /opt/cafi-openssl/ssl \
    && printf '%s\n' 'openssl_conf = openssl_init' '[openssl_init]' 'providers = providers' \
       '[providers]' 'default = default_provider' '[default_provider]' 'activate = 1' \
       > /opt/cafi-openssl/ssl/openssl.cnf
WORKDIR /workspace
COPY spikes/environment.py /opt/cafi/environment.py
CMD ["python", "/opt/cafi/environment.py"]
