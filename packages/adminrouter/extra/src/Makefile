DCOS_OPEN_PATH := $(shell cat $(CURDIR)/.dcos-open.path)
AR_OPEN_PATH := ${DCOS_OPEN_PATH}/packages/adminrouter/extra/src/

.PHONY: apply-open
apply-open:
	# We use rsync due to the fact that directory copying in the loop is
	# confusing plain `cp`
	-cp -vR ${AR_OPEN_PATH}../../docker/ ../../
	mkdir -v errorpages/ || true
	for f in \
			.flake8 \
			.isort.cfg \
			Makefile.common \
			common/disable-response_caching.conf \
			common/websockets.conf \
			errorpages/ \
			lib/ \
			mime.types \
			pytest.ini \
			test-harness/ \
			; \
		do \
		rsync -av ${AR_OPEN_PATH}$${f} ./$${f} --exclude 'logs/*' --exclude '.*.s??'; \
	done
	rm -vR ./test-harness/tests/open


-include Makefile.common
