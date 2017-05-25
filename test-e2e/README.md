This directory contains PoC end to end tests.

To run these tests, create an environment which can run DC/OS Docker as per the [README](https://github.com/dcos/dcos-docker/blob/master/README.md#requirements).

Then, download DC/OS Docker and the relevant build artifact as per the [DC/OS E2E README](https://github.com/adamtheturtle/dcos-e2e#test-environment).
For example, at the time of writing:

```sh
ARTIFACT_URL=https://downloads.mesosphere.com/dcos-enterprise/testing/pull/930/dcos_generate_config.ee.sh
DCOS_DOCKER_REPOSITORY=https://github.com/dcos/dcos-docker.git
DCOS_DOCKER_BRANCH=master

ARTIFACT_PATH=/tmp/dcos_generate_config.sh
DCOS_DOCKER_PATH=/tmp/dcos-docker

rm -rf $ARTIFACT_PATH
rm -rf $DCOS_DOCKER_PATH
curl -o $ARTIFACT_PATH $ARTIFACT_URL
git clone -b $DCOS_DOCKER_BRANCH $DCOS_DOCKER_REPOSITORY $DCOS_DOCKER_PATH
```

Then, install the test dependencies, preferably in a virtual environment:

```sh
pip install -r requirements.txt
```

and run the tests:

```sh
pytest
```
