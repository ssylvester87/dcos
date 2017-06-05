DCOS_OPEN_PATH := $(shell cat $(CURDIR)/.dcos-open.path)
AR_OPEN_PATH := ${DCOS_OPEN_PATH}/packages/adminrouter/extra/src/

.PHONY: apply-open
apply-open:
	# No point in continuing
	test -f $(CURDIR)/.dcos-open.path
	# We use rsync due to the fact that directory copying in the loop is
	# confusing plain `cp`
	mkdir -v errorpages/ || true
	for f in \
			.flake8 \
			.isort.cfg \
			Makefile.common \
			includes/ \
			errorpages/ \
			lib/ \
			mime.types \
			pytest.ini \
			test-harness/ \
			; \
		do \
		rsync -av ${AR_OPEN_PATH}$${f} ./$${f} --exclude 'logs/*' --exclude '.*.s??'; \
	done
	# Remove all the files related to Open AR
	for d in \
		./test-harness/modules/mocker/endpoints/open/ \
		./test-harness/tests/open/ \
		./includes/http/open/ \
		./includes/server/open/ \
		./includes/main/open/ \
		./test-harness/modules/mocker/open.py \
		./test-harness/modules/runner/open.py \
		./test-harness/modules/generic_test_code/open.py \
		./lib/auth/open.lua \
		; \
	do \
		rm -vRf $${d}; \
	done

-include Makefile.common
