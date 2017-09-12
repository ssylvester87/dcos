class CustomCAPrivateKeyMissingError(Exception):
    """
    An error that is raised when a cluster is installed with a custom CA
    certificate and the corresponding private key file cannot be read.
    """
    pass
