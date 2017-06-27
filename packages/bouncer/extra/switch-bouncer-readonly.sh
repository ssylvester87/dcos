#!/usr/bin/env bash

# This script runs the bouncer `readonly` script after loading the bouncer
# environment.

# It is expected that this command is run in the `dcos-shell` environment.

# Configure environment variables for the `readonly` script to use.
# This mimics the EnvironmentFile= and Environment= directives in the
# dcos-bouncer.service unit file.

## Export the variables listed in the bouncer environment file.
set -a
source /run/dcos/etc/bouncer
set +a
export BOUNCER_CONFIG_CLASS=DCOSConfig
export BOUNCER_CONFIG_FILE_PATH=/opt/mesosphere/etc/bouncer-config.json
export SECRET_KEY_FILE_PATH=/run/dcos/pki/tls/private/bouncer.key

/opt/mesosphere/active/bouncer/bouncer/upgrade/bin/readonly "$*"
