#!/usr/bin/env bash
set -xe

SECRETS_PORT=1337
SECRETS_ADVERTISE_ADDR=https://$($MESOS_IP_DISCOVERY_COMMAND)/secrets/v1

EXTRA_FLAGS=

if [[ "${SECRETS_BOOTSTRAP}" == "true" ]]; then
	EXTRA_FLAGS=--bootstrap
fi

# TODO need to do $PKG_PATH here and envsubst in build
exec /opt/mesosphere/bin/secrets -d -port ${SECRETS_PORT} --advertise-addr ${SECRETS_ADVERTISE_ADDR} ${EXTRA_FLAGS}
