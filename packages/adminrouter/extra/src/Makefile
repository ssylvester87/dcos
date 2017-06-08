DCOS_OPEN_PATH := $(shell cat $(CURDIR)/.dcos-open.path 2>/dev/null)
AR_OPEN_PATH := ${DCOS_OPEN_PATH}/packages/adminrouter/extra/src/

.PHONY: apply-open
apply-open:
ifeq ($(AR_OPEN_PATH),/packages/adminrouter/extra/src/)
		$(error Reference to Open DC/OS repo has not been found, please check https://github.com/mesosphere/dcos-enterprise/tree/master/packages/adminrouter/extra/src#applying-overlay)
endif
	@# We use rsync due to the fact that directory copying in the loop is
	@# confusing plain `cp`
	@mkdir errorpages/ 2>/dev/null|| true
	@for f in \
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
		rsync -a ${AR_OPEN_PATH}$${f} ./$${f} --exclude 'logs/*' --exclude '.*.s??'; \
	done
	@# Remove all the files related to Open AR
	@for d in \
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
		rm -Rf $${d}; \
	done

-include Makefile.common
