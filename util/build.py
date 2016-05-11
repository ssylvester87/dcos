#!/usr/bin/env python3.4
from subprocess import check_call

# Checkout dcos upstream at the right commit
check_call(['util/fetch_dcos.py'])

# Move the config file into place
check_call(['cp', 'config/dcos-release.config.yaml', 'dcos-release.config.yaml'])

# Do a build
check_call(['ext/upstream/build_teamcity'])
