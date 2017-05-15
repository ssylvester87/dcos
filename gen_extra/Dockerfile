FROM python:3.5.2

# Install required OpenSSL binary version
RUN set -ex && \

    # Install required OpenSSL binary version
    curl -L -O https://www.openssl.org/source/openssl-1.0.2k.tar.gz && \
    tar xzf openssl-1.0.2k.tar.gz && \
    cd openssl-1.0.2k && \

    # Compile new version
    ./config && \
    make && \

    # Install openssl
    make install && \
    mv /usr/bin/openssl /usr/bin/openssl-old && \
    ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl && \

    # Cleanup
    cd .. && \
    rm -rf openssl-1.0.2k* && \

    # Prepare mount directory with dcos-enterprise source code
    mkdir -p /dcos-enterprise

WORKDIR /dcos-enterprise
