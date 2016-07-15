TOP := $(dir $(lastword $(MAKEFILE_LIST)))

.PHONY: test install clean

# You might like: make PYTEST_OPTS="-s -v" test
PYTEST_OPTS := -v

test: export MESOS_IP_DISCOVERY_COMMAND = $(TOP)/tests/ip-detect
test: install
	rm -rf tmp && \
	source venv/bin/activate && \
	py.test $(PYTEST_OPTS) tests

install: venv
	source venv/bin/activate && \
	python setup.py develop

venv: requirements.txt
	pyvenv venv
	source venv/bin/activate && \
	pip install --upgrade pip && \
	pip install -r requirements.txt

clean:
	rm -rf venv tmp

.DEFAULT_GOAL := test
