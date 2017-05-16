#!/bin/bash
set -euo pipefail
TLS_ENABLED=${TLS_ENABLED:-false}

export HOST_IP=$($MESOS_IP_DISCOVERY_COMMAND)
export MARATHON_HOSTNAME=$HOST_IP
export LIBPROCESS_IP=$HOST_IP

MARATHON_JAVA_ARGS=
MARATHON_TLS_ARGS=
if [ "${TLS_ENABLED-}" = "true" ]; then
    MARATHON_JAVA_ARGS=-Djavax.net.ssl.trustStore=${TLS_TRUSTSTORE}
    MARATHON_TLS_ARGS="--ssl_keystore_path ${SSL_KEYSTORE_PATH} --ssl_keystore_password ${SSL_KEYSTORE_PASSWORD}"
fi

MARATHON_EXTRA_ARGS="${MARATHON_EXTRA_ARGS-} --mesos_user ${MESOS_USER}"
MARATHON_EXTRA_ARGS="${MARATHON_EXTRA_ARGS-} --mesos_authentication_principal dcos_marathon"
if [ "${MESOS_FRAMEWORK_AUTHN-}" = "true" ]; then
    MARATHON_EXTRA_ARGS="${MARATHON_EXTRA_ARGS-} --mesos_authentication"
fi

exec /opt/mesosphere/bin/java \
    -Xmx2G \
    $MARATHON_JAVA_ARGS \
    -jar "$PKG_PATH/usr/marathon.jar" \
    --plugin_dir "$PKG_PATH/usr/plugins/lib" \
    --plugin_conf "$PKG_PATH/usr/plugins/plugin-conf.json" \
    --zk "$MARATHON_ZK" \
    --master zk://zk-1.zk:2181,zk-2.zk:2181,zk-3.zk:2181,zk-4.zk:2181,zk-5.zk:2181/mesos \
    --hostname "$MARATHON_HOSTNAME" \
    --default_accepted_resource_roles "*" \
    --mesos_role "slave_public" \
    --max_tasks_per_offer 100 \
    --task_launch_timeout 86400000 \
    --decline_offer_duration 300000 \
    --revive_offers_for_new_apps \
    --zk_compression \
    --mesos_leader_ui_url "/mesos" \
    --enable_features "vips,task_killing,external_volumes,secrets,gpu_resources" \
    $MARATHON_TLS_ARGS \
    $MARATHON_EXTRA_ARGS
