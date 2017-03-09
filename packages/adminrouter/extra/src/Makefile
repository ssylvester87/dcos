DCOS_OPEN_PATH := $(shell cat $(CURDIR)/.dcos-open.path)
AR_OPEN_PATH := ${DCOS_OPEN_PATH}/packages/adminrouter/extra/src/

.PHONY: apply-open
apply-open:
	# We use rsync due to the fact that directory copying in the loop is
	# confusing plain `cp`
	cp -vR ${AR_OPEN_PATH}../../docker/ ../../
	for f in \
			.flake8 \
			Makefile.common \
			master/agent.lua \
			master/cache.lua \
			master/marathon-leader.lua \
			mime.types \
			pytest.ini \
			resty/http.lua \
			resty/http_headers.lua \
			resty/lock.lua \
			test-harness/ \
			; \
		do \
		rsync -av ${AR_OPEN_PATH}$${f} ./$${f}; \
	done
	rm -vR ./test-harness/tests/open


-include Makefile.common
