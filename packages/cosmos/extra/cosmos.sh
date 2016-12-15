#!/bin/bash
set -euo pipefail
TLS_ENABLED=${TLS_ENABLED:-false}

if [ "${TLS_ENABLED-}" = "true" ]; then
    TLS_PORT=${TLS_PORT:-7443}
    TLS_KEY_FILE=${TLS_KEY_FILE:-/run/dcos/pki/tls/private/cosmos.key}
    TLS_CERT_FILE=${TLS_CERT_FILE:-/run/dcos/pki/tls/certs/cosmos.crt}
    TLS_TRUSTSTORE=${TLS_TRUSTSTORE:-/run/dcos/pki/CA/certs/cacerts_cosmos.jks}
    ADMINROUTER_URI=${ADMINROUTER_URI:-https://master.mesos}
    MARATHON_URI=${MARATHON_URI:-https://master.mesos:8443}
    MESOSMASTER_URI=${MESOSMASTER_URI:-https://leader.mesos:5050}
    ZOOKEEPER_URI=${ZOOKEEPER_URI:-zk://localhost:2181/cosmos}
    exec /opt/mesosphere/bin/java \
        -Xmx2G \
        -Djavax.net.ssl.trustStore=${TLS_TRUSTSTORE} \
        -classpath $PKG_PATH/usr/cosmos.jar \
        com.simontuffs.onejar.Boot \
        -admin.port=127.0.0.1:9990 \
        -io.github.benwhitehead.finch.httpInterface= \
        -io.github.benwhitehead.finch.httpsInterface=0.0.0.0:${TLS_PORT} \
        -io.github.benwhitehead.finch.certificatePath=${TLS_CERT_FILE} \
        -io.github.benwhitehead.finch.keyPath=${TLS_KEY_FILE} \
        -com.mesosphere.cosmos.adminRouterUri=${ADMINROUTER_URI} \
        -com.mesosphere.cosmos.marathonUri=${MARATHON_URI} \
        -com.mesosphere.cosmos.mesosMasterUri=${MESOSMASTER_URI} \
        -com.mesosphere.cosmos.zookeeperUri=${ZOOKEEPER_URI} \
        ${COSMOS_STAGED_PACKAGE_STORAGE_URI_FLAG} \
        ${COSMOS_PACKAGE_STORAGE_URI_FLAG}

else
    exec /opt/mesosphere/bin/java \
        -Xmx2G \
        -classpath $PKG_PATH/usr/cosmos.jar \
        com.simontuffs.onejar.Boot \
        -admin.port=127.0.0.1:9990 \
        ${COSMOS_STAGED_PACKAGE_STORAGE_URI_FLAG} \
        ${COSMOS_PACKAGE_STORAGE_URI_FLAG}
fi
