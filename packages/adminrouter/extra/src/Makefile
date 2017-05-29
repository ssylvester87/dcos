DCOS_OPEN_PATH := $(shell cat $(CURDIR)/.dcos-open.path)
AR_OPEN_PATH := ${DCOS_OPEN_PATH}/packages/adminrouter/extra/src/

.PHONY: apply-open
apply-open:
	# We use rsync due to the fact that directory copying in the loop is
	# confusing plain `cp`
	mkdir -v resty/ errorpages/ || true
	for f in \
			.flake8 \
			.isort.cfg \
			Makefile.common \
			common/auth/ \
			errorpages/ \
			master/agent.lua \
			master/cache.lua \
			master/marathon-leader.lua \
			master/history-service.lua \
			mime.types \
			pytest.ini \
			resty/ \
			test-harness/ \
			; \
		do \
		rsync -av ${AR_OPEN_PATH}$${f} ./$${f}; \
	done
	rm -vR ./test-harness/tests/open


-include Makefile.common
