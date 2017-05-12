#!/bin/bash
set -euo pipefail
TLS_ENABLED=${TLS_ENABLED:-false}

if [ "${TLS_ENABLED-}" = "true" ]; then
    TLS_TRUSTSTORE=${TLS_TRUSTSTORE:-/run/dcos/pki/CA/certs/cacerts_cosmos.jks}
    ADMINROUTER_URI=${ADMINROUTER_URI:-https://master.mesos}
    MARATHON_URI=${MARATHON_URI:-https://master.mesos:8443}
    MESOSMASTER_URI=${MESOSMASTER_URI:-https://leader.mesos:5050}
    ZOOKEEPER_URI=${ZOOKEEPER_URI:-zk://localhost:2181/cosmos}
    exec /opt/mesosphere/bin/java \
        -Xmx2G \
        -Djavax.net.ssl.trustStore=${TLS_TRUSTSTORE} \
        -Djdk.http.auth.tunneling.disabledSchemes="" \
        -classpath $PKG_PATH/usr/cosmos.jar \
        com.simontuffs.onejar.Boot \
          -admin.port=127.0.0.1:9990 \
          -io.github.benwhitehead.finch.httpInterface=127.0.0.1:7070 \
          -com.mesosphere.cosmos.adminRouterUri=${ADMINROUTER_URI} \
          -com.mesosphere.cosmos.marathonUri=${MARATHON_URI} \
          -com.mesosphere.cosmos.mesosMasterUri=${MESOSMASTER_URI} \
          -com.mesosphere.cosmos.zookeeperUri=${ZOOKEEPER_URI} \
          -com.mesosphere.cosmos.dataDir=/var/lib/dcos/cosmos
else
    exec /opt/mesosphere/bin/java \
        -Xmx2G \
        -Djdk.http.auth.tunneling.disabledSchemes="" \
        -classpath $PKG_PATH/usr/cosmos.jar \
        com.simontuffs.onejar.Boot \
          -admin.port=127.0.0.1:9990 \
          -io.github.benwhitehead.finch.httpInterface=127.0.0.1:7070 \
          -com.mesosphere.cosmos.dataDir=/var/lib/dcos/cosmos
fi
