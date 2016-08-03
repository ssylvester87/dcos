#!/usr/bin/env bash
set -xe

# TODO move this to bootstrap or ExecStartPre when we have
# a separate OS user for vault
VAULT_ADVERTISE_ADDR=https://$($MESOS_IP_DISCOVERY_COMMAND)/vault/default
sed \
  -e "s#VAULT_ZNODE_OWNER#$VAULT_ZNODE_OWNER#g" \
  -e "s#VAULT_AUTH_INFO#$VAULT_AUTH_INFO#g" \
  -e "s#VAULT_ADVERTISE_ADDR#$VAULT_ADVERTISE_ADDR#g" \
  /opt/mesosphere/etc/vault/config.hcl > /run/dcos/etc/vault.hcl

# TODO need to do $PKG_PATH here and envsubst in build
exec /opt/mesosphere/bin/vault server -config=/run/dcos/etc/vault.hcl -log-level=trace
