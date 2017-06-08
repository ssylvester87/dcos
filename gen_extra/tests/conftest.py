# Copyright (C) Mesosphere, Inc. See LICENSE file for details.

import os
import sys

# Precisely control import.
parent = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.dirname(parent))
