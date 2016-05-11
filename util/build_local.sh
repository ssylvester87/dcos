#!/bin/bash

./util/fetch_dcos.py


mkdir -p cache

if [ ! -e dcos-release.config.yaml ]
then
  echo "ERROR: Must make a dcos-release.config.yaml. See https://github.com/dcos/dcos#setup-a-build-environment for examples."
  exit 1
fi

if [ ! -e cache/build_venv ]
then
    rm -rf cache/build_venv
fi

pyvenv cache/build_venv

source cache/build_venv/bin/activate

pushd ext/upstream
./prep_local
popd

release create `whoami` local_build
