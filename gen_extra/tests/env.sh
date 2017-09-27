#!/usr/bin/env bash

set -x
set -o errexit -o pipefail

./util/fetch_dcos.py

mkdir -p cache

if [ ! -e cache/build_venv ]
then
    rm -rf cache/build_venv
fi

pyvenv cache/build_venv
source cache/build_venv/bin/activate

pushd ext/upstream
./prep_local
popd

# TODO(mh): Figure out how to install without adding it to dcos/setup.py
pip3 install cryptography==1.7.2
pip3 install pytest-catchlog

echo "Enviroment is ready"
