This directory contains end to end tests.

To run these tests, create an environment which can run DC/OS Docker as per the [DC/OS Docker README](https://github.com/dcos/dcos-docker/blob/master/README.md#requirements).

Then, download the relevant build artifact as per the [DC/OS E2E README](https://github.com/adamtheturtle/dcos-e2e#test-environment).
For example, at the time of writing:

```sh
ARTIFACT_URL=https://downloads.mesosphere.com/dcos-enterprise/testing/master/dcos_generate_config.ee.sh
export DCOS_E2E_GENCONF_PATH=/tmp/dcos_generate_config.sh
export DCOS_E2E_TMP_DIR_PATH=/tmp

rm -rf $DCOS_E2E_GENCONF_PATH
curl -o $DCOS_E2E_GENCONF_PATH $ARTIFACT_URL
```

Then, install the test dependencies, preferably in a virtual environment:

```sh
pip install -r requirements.txt
```

and run the tests:

```sh
pytest
```
