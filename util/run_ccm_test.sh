#!/bin/bash
# Note: dcos-image must be installed to access ccm-deploy-test
set -euo pipefail
set -x
export TEST_ADD_ENV_DCOS_LOGIN_UNAME=testadmin
export TEST_ADD_ENV_DCOS_LOGIN_PW=testpassword
export TEST_ADD_CONFIG=$PWD/add_config.yaml

password_hash='$6$rounds=656000$WZdTPdpxUZsDG5PG$6om6ApIm5l5639JNAUmtFD87cIXdWCAVKeJ4zNlhmPKWT3PARF6Ai.HpcjR8SPQSQnqoefBiLaZmPuMFhGhpm0'

cat <<EOF > add_config.yaml
---
customer_key: 12345
superuser_username: testadmin
superuser_password_hash: $password_hash
EOF

ccm-deploy-test
