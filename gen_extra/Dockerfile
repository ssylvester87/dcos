# Dockerfile for building environment with all dependencies required for
# running `gen_extra` unit tests. On top of python `3.5.2` we're building
# custom `openssl` version from `1.0.2` line to match version provided
# by DC/OS build.
# The dcos-enterprise should be bind-mounted to `/dcos-enterprise` directory.
FROM python:3.5.2

RUN set -ex && \

    # Install required OpenSSL binary version
    echo "deb http://ftp.debian.org/debian jessie-backports main" > /etc/apt/sources.list.d/jessie-backports.list && \
    apt-get update && \
    apt-get -t jessie-backports install -y openssl && \

    # Prepare mount directory with dcos-enterprise source code
    mkdir -p /dcos-enterprise

WORKDIR /dcos-enterprise
