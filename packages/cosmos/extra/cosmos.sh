#!/bin/bash
set -euo pipefail
TLS_ENABLED=${TLS_ENABLED:-false}
DISABLED_PROXY_SCHEMES='-Djdk.http.auth.tunneling.disabledSchemes="NTLM"'

if [ "${TLS_ENABLED-}" = "true" ]; then
    TLS_TRUSTSTORE=${TLS_TRUSTSTORE:-/run/dcos/pki/CA/certs/cacerts_cosmos.jks}
    ADMINROUTER_URI=${ADMINROUTER_URI:-https://master.mesos}
    MARATHON_URI=${MARATHON_URI:-https://master.mesos:8443}
    MESOSMASTER_URI=${MESOSMASTER_URI:-https://leader.mesos:5050}
    ZOOKEEPER_URI=${ZOOKEEPER_URI:-zk://zk-1.zk:2181,zk-2.zk:2181,zk-3.zk:2181,zk-4.zk:2181,zk-5.zk:2181/cosmos}
    exec /opt/mesosphere/bin/java \
        -Xmx2G \
        -Djavax.net.ssl.trustStore=${TLS_TRUSTSTORE} \
        "${DISABLED_PROXY_SCHEMES}" \
        -classpath $PKG_PATH/usr/cosmos.jar \
        com.simontuffs.onejar.Boot \
        -admin.port=127.0.0.1:9990 \
        -com.mesosphere.cosmos.httpInterface=127.0.0.1:7070 \
        -com.mesosphere.cosmos.adminRouterUri=${ADMINROUTER_URI} \
        -com.mesosphere.cosmos.marathonUri=${MARATHON_URI} \
        -com.mesosphere.cosmos.mesosMasterUri=${MESOSMASTER_URI} \
        -com.mesosphere.cosmos.zookeeperUri=${ZOOKEEPER_URI} \
        ${COSMOS_STAGED_PACKAGE_STORAGE_URI_FLAG} \
        ${COSMOS_PACKAGE_STORAGE_URI_FLAG}

else
    exec /opt/mesosphere/bin/java \
        -Xmx2G \
        "${DISABLED_PROXY_SCHEMES}" \
        -classpath $PKG_PATH/usr/cosmos.jar \
        com.simontuffs.onejar.Boot \
        -admin.port=127.0.0.1:9990 \
        -com.mesosphere.cosmos.httpInterface=127.0.0.1:7070 \
        ${COSMOS_STAGED_PACKAGE_STORAGE_URI_FLAG} \
        ${COSMOS_PACKAGE_STORAGE_URI_FLAG}
fi
