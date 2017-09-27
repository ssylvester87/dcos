# Repository is one level above this directory
DCOS_EE_PATH := $(dir $(CURDIR))

DEVKIT_CONTAINER_NAME := dcos-ee-gen_extra-devkit

DEVKIT_COMMON_DOCKER_OPTS := --name $(DEVKIT_CONTAINER_NAME) \
	-v $(DCOS_EE_PATH):/dcos-enterprise

.PHONY: help
help:
	@echo "Please check README.md for usage."

.PHONY: clean-devkit-container
clean-devkit-container:
	-docker rm -vf $(DEVKIT_CONTAINER_NAME) > /dev/null 2>&1

.PHONY: clean-containers
clean-containers: clean-devkit-container

.PHONY: clean
clean: clean-devkit-container

.PHONY: devkit
devkit:
	if $$(docker images | grep mesosphereci/$(DEVKIT_CONTAINER_NAME) | grep -q full); then \
		echo "+ Devkit image already built"; \
	else \
		echo "+ Building devkit image"; \
		set -ex ; \
		docker build --rm --force-rm -t mesosphereci/$(DEVKIT_CONTAINER_NAME):tmp $(CURDIR)/; \
		docker build --rm --force-rm \
			-t mesosphereci/$(DEVKIT_CONTAINER_NAME):tmp $(CURDIR)/; \
		docker run \
			$(DEVKIT_COMMON_DOCKER_OPTS) \
			mesosphereci/$(DEVKIT_CONTAINER_NAME):tmp /bin/bash -c " \
				/dcos-enterprise/gen_extra/tests/env.sh \
			" && \
		docker commit $$(docker ps -a -q -f name=$(DEVKIT_CONTAINER_NAME)) \
			mesosphereci/$(DEVKIT_CONTAINER_NAME):full ; \
		docker rm -f $(DEVKIT_CONTAINER_NAME) ; \
		docker rmi -f mesosphereci/$(DEVKIT_CONTAINER_NAME):tmp ; \
	fi

.PHONY: shell
shell: devkit clean
	docker run --rm -it \
		$(DEVKIT_COMMON_DOCKER_OPTS) \
		mesosphereci/$(DEVKIT_CONTAINER_NAME):full /bin/bash

.PHONY: test
test: devkit clean
	docker run --rm \
		$(DEVKIT_COMMON_DOCKER_OPTS) \
		mesosphereci/$(DEVKIT_CONTAINER_NAME):full /bin/bash -x -c " \
			source cache/build_venv/bin/activate && \
			pytest --no-print-logs gen_extra/ \
		"

.PHONY: stop
stop: clean-containers

.PHONY: update-devkit
update-devkit:
	@echo "Updating devkit image"
	docker build --rm --force-rm \
		-t mesosphereci/$(DEVKIT_CONTAINER_NAME):tmp $(CURDIR)/
	docker run \
		$(DEVKIT_COMMON_DOCKER_OPTS) \
		mesosphereci/$(DEVKIT_CONTAINER_NAME):tmp /bin/bash -c " \
			/dcos-enterprise/gen_extra/tests/env.sh \
		" && \
	docker commit $$(docker ps -a -q -f name=$(DEVKIT_CONTAINER_NAME)) \
		mesosphereci/$(DEVKIT_CONTAINER_NAME):full
	docker rm -f $(DEVKIT_CONTAINER_NAME)
	docker rmi -f mesosphereci/$(DEVKIT_CONTAINER_NAME):tmp
