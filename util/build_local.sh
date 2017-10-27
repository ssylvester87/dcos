#!/bin/bash

set -x
set -o errexit -o pipefail

./util/fetch_dcos.py

mkdir -p cache

if [ ! -e dcos-release.config.yaml ]
then
cat <<EOF > dcos-release.config.yaml
storage:
  local:
    kind: local_path
    path: $HOME/dcos-artifacts
options:
  preferred: local
  cloudformation_s3_url: https://s3-us-west-2.amazonaws.com/downloads.dcos.io/dcos
EOF
fi

if [ ! -e cache/build_venv ]
then
    rm -rf cache/build_venv
fi

python3.5 -m venv cache/build_venv

source cache/build_venv/bin/activate

pushd ext/upstream
./prep_local
popd

release create `whoami` local_build
