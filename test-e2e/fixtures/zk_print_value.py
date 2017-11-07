import argparse
from typing import Optional

from kazoo.client import KazooClient
from kazoo.retry import KazooRetry

parser = argparse.ArgumentParser(
    description='Reads zookeeper node value and prints it as a text')
parser.add_argument('path', type=str, nargs=1)

digest_auth = parser.add_mutually_exclusive_group()
digest_auth.add_argument(
    '--digest-auth', type=str, nargs=1)
digest_auth.add_argument(
    '--digest-auth-file', type=argparse.FileType('rb', 0), nargs=1)

parser.add_argument('--zk', type=str, nargs=1, required=True)


def zk_print_value(path: str, zk: str, digest_auth: Optional[str]=None) -> None:
    """
    Reads a value from Zookeeper and prints it to the stdout. This function
    assumes that a value is a UTF-8 encoded string.

    Args:
        path: A path in ZK that value should be printed
        zk: A ZK connection string, i.e. zk-1:2181,zk-2:2181
        digest_auth: Optionally an authentication string in format
            username:password for digest authentication.
    """
    conn_retry_policy = KazooRetry(max_tries=-1, delay=0.1, max_delay=0.1)
    cmd_retry_policy = KazooRetry(
        max_tries=3, delay=0.3, backoff=1, max_delay=1, ignore_expire=False)
    zk = KazooClient(
        hosts=zk, connection_retry=conn_retry_policy, command_retry=cmd_retry_policy)
    zk.start()
    if digest_auth:
        zk.add_auth('digest', args.digest_auth)

    value, _ = zk.get(path)
    print(value.decode('utf-8'))


if __name__ == "__main__":
    args = parser.parse_args()

    # If file was provided read the digest auth value
    if args.digest_auth_file:
        path = args.digest_auth_file[0]
        args.digest_auth = path.read().decode('utf-8').strip()

    zk_print_value(
        path=args.path[0], zk=args.zk[0], digest_auth=args.digest_auth)
