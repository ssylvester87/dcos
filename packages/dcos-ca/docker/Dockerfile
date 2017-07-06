FROM dcos/dcos-builder:dcos-builder_dockerdir-latest

ENV USER root


#### Tests related things, not strictly needed for building:
COPY ./sample-config/ /opt/ca-config/
WORKDIR /opt/ca-config/
RUN openssl req \
        -x509 \
        -newkey rsa:2048 \
        -keyout ca-cert.key \
        -out ca-cert.pem \
        -days 365 \
        -nodes \
        -subj "/C=ZZ/ST=MyState/L=MyLand/O=Potato Corp./OU=IT Department/CN=potato.com"

RUN /bin/bash -x -c 'for i in {1..5}; do apt-get update && break || sleep 2; done'
RUN go get github.com/GeertJohan/fgt \
        && go get github.com/golang/lint/golint \
        && go get github.com/derekparker/delve/cmd/dlv
#FIXME gometalinter when we sanitize source more


#### Stuff usefull while debugging docker container, not strictly needed for
#### building:
RUN apt-get install -y --no-install-recommends \
        vim \
        telnet \
        apt-file \
        dnsutils \
        less


#### Patching ZK bindings
#
# Special care goes for ZK bindings as there is a bug preventing
# dcos-ca/libzookeeper running under CoreOS with logging enabled.
# YES, the build process will be painfully long :(
# This will go away as soon as https://github.com/apache/zookeeper/pull/70
# gets merged and debian catches up or we move it into separate dcos-wide
# package that will supply unified libzookeeper for all components.
# For now we need it here:

RUN apt-get install \
        -y \
        --no-install-recommends \
        lsb-release \
        dpkg-dev

# Install gcc 4.9 toolchain
RUN apt-get install -y gcc-4.9 g++-4.9 cpp-4.9 \
        && ln -sf /usr/bin/gcc-4.9 /usr/bin/gcc \
        && ln -sf /usr/bin/cpp-4.9 /usr/bin/cpp \
        && ln -sf /usr/bin/g++-4.9 /usr/bin/g++

RUN echo "deb-src http://archive.ubuntu.com/ubuntu/ xenial main" >> /etc/apt/sources.list \
        && echo "deb-src http://archive.ubuntu.com/ubuntu/ xenial-updates main" >> /etc/apt/sources.list \
        && echo "deb-src http://archive.ubuntu.com/ubuntu/ xenial-security main" >> /etc/apt/sources.list \
        && /bin/bash -x -c 'for i in {1..5}; do apt-get update && break || sleep 2; done'
COPY libzookeeper_mt2-no_glibc.patch /buildir/
RUN cd /buildir/ \
        && apt-get source libzookeeper-mt2 \
        && apt-get build-dep -y libzookeeper-mt2 \
        && cd zookeeper*/ \
        && patch -p1 < ../libzookeeper_mt2-no_glibc.patch \
        && dpkg-buildpackage  -uc -b \
        && dpkg -i ../libzookeeper-mt-dev*.deb ../libzookeeper-mt2*.deb


#### ZKVFS deps
RUN apt-get install -y --no-install-recommends \
        cmake \
        libreadline6 \
        libreadline6-dev \
        libsqlite3-0 \
        libsqlite3-dev \
        libssl-dev \
        python3-pip \
        clang

# DCOS-CA port:
EXPOSE 8888

# Just shell, dcos-ca can be run via Makefile:
CMD ["/bin/bash"]
