# Copyright (C) Mesosphere, Inc. See LICENSE file for details.


def parse_dotenv(path):
    """Parse environment file as used by systemd.

    Args:
        path: dot env file path

    Returns:
        Generator(key, value)

    Remarks:
        Mostly copied from https://github.com/theskumar/python-dotenv/blob/master/dotenv/main.py#L94
    """

    with open(path) as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith('#') or '=' not in line:
                continue

            key, value = line.split('=', 1)

            # Remove any leading and trailing spaces in key, value
            key, value = key.strip(), value.strip()

            if len(value) > 0:
                quoted = value[0] == value[-1] == '"'
                if quoted:
                    value = value[1:-1]

            yield key, value
