FROM python:3.5.2

ENV OPENSSL_VERSION 1.0.2l
ENV OPENSSL_URL https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
ENV OPENSSL_SHA256 ce07195b659e75f4e1db43552860070061f156a98bb37b672b101ba6e3ddf30c

# Install required OpenSSL binary version
RUN set -ex && \

    # Install required OpenSSL binary version
    curl -L -O ${OPENSSL_URL} && \
    echo "${OPENSSL_SHA256} openssl-${OPENSSL_VERSION}.tar.gz" > openssl-${OPENSSL_VERSION}.tar.gz.sha256 && \
    sha256sum -c openssl-${OPENSSL_VERSION}.tar.gz.sha256 &&  \

    # Build OpenSSL
    tar xzf openssl-${OPENSSL_VERSION}.tar.gz && \
    cd openssl-${OPENSSL_VERSION} && \

    # Compile new version
    ./config && \
    make && \

    # Install openssl
    make install && \
    mv /usr/bin/openssl /usr/bin/openssl-old && \
    ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl && \

    # Cleanup
    cd .. && \
    rm -rf ${OPENSSL_VERSION}* && \

    # Prepare mount directory with dcos-enterprise source code
    mkdir -p /dcos-enterprise

WORKDIR /dcos-enterprise
