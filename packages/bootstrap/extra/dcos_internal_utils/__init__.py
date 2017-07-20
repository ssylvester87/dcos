# Note(JP): This file system path must now be treated like a public interface.
# It is consumed by various DC/OS-internal components, but is also being
# referred to in the public-facing documentation of Enterprise DC/OS. For
# background see DCOS-16542.
DCOS_CA_TRUST_BUNDLE_FILE_PATH = '/run/dcos/pki/CA/ca-bundle.crt'


from . import bootstrap  # noqa
from . import ca  # noqa
from . import exhibitor  # noqa
from . import iam  # noqa
from . import utils  # noqa
