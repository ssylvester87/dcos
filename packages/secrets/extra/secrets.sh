#!/usr/bin/env bash
set -xe
TLS_ENABLED=${TLS_ENABLED:-false}

if [[ "${TLS_ENABLED}" == "true" ]]; then
    SECRETS_ADVERTISE_ADDR=https://$($MESOS_IP_DISCOVERY_COMMAND)/secrets/v1
else
    SECRETS_ADVERTISE_ADDR=http://$($MESOS_IP_DISCOVERY_COMMAND)/secrets/v1
fi

EXTRA_FLAGS=

if [[ "${SECRETS_BOOTSTRAP}" == "true" ]]; then
    EXTRA_FLAGS=--bootstrap
fi

if [[ "${TLS_ENABLED}" == "true" ]]; then
    EXTRA_FLAGS+=" --key ${TLS_KEY_FILE} --cert ${TLS_CERT_FILE} --CA ${TLS_CA_FILE}"
fi

# TODO need to do $PKG_PATH here and envsubst in build
exec /opt/mesosphere/bin/secrets -d -listen-addr 127.0.0.1 -listen-port 1337 --advertise-addr ${SECRETS_ADVERTISE_ADDR} ${EXTRA_FLAGS}
