#!/bin/bash
# Note: dcos-image must be pip installed to access ccm-deploy-test
set -euo pipefail
set -x
export TEST_ADD_ENV_DCOS_LOGIN_UNAME=testadmin
export TEST_ADD_ENV_DCOS_LOGIN_PW=testpassword
export TEST_ADD_ENV_PYTHONDONTWRITEBYTECODE="true"
export TEST_ADD_ENV_PYTHONUNBUFFERED="true"
export TEST_ADD_CONFIG=$PWD/add_config.yaml

password_hash='$6$rounds=656000$WZdTPdpxUZsDG5PG$6om6ApIm5l5639JNAUmtFD87cIXdWCAVKeJ4zNlhmPKWT3PARF6Ai.HpcjR8SPQSQnqoefBiLaZmPuMFhGhpm0'

cat <<EOF > add_config.yaml
---
customer_key: 123456-78901-234567-89012345-6789012
superuser_username: testadmin
superuser_password_hash: $password_hash
security: $DCOS_SECURITY
EOF

# pip installed command to run tests
# source in dcos/dcos calls: test_util.test_installer_ccm:main
ccm-deploy-test
