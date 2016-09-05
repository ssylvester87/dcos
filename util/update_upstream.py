"""
Usage: python update_upstream.py

Description:

1. Picks the latest master SHA of git@github.com/dcos/dcos.git
2. Creates an integration branch integrate_upstream/SHA in dcos-enterprise.
3. Updates packages/upstream.json to the SHA grabbed in step 1.
4. Pushes integrate_upstream/SHA for testing by TeamCity.
"""

import json
import sys

from subprocess import CalledProcessError, check_output


def execute(proc):
    assert isinstance(proc, list)
    try:
        return check_output(proc)
    except CalledProcessError as exp:
        print("failed executing: {cmd}\n {exception}".format(cmd=str(proc), exception=str(exp)))
        sys.exit(1)


def get_latest_sha():
    try:
        remote_master = execute(["git", "ls-remote", "git@github.com:dcos/dcos.git", "refs/heads/master"])
        sha, _ = remote_master.split()
        return sha.decode("utf-8")
    except ValueError as exp:
        print("Unable to determine the latest SHA.\n{exception}".format(exception=str(exp)))

    return None


def update_upstream_json(sha):
    with open("packages/upstream.json", "r+") as upstream_json_fh:
        upstream_contents = json.load(upstream_json_fh)
        upstream_contents["ref"] = sha

        upstream_json_fh.seek(0)
        json.dump(upstream_contents, upstream_json_fh, indent=2, sort_keys=True)
        upstream_json_fh.write("\n")        # newline at the end of file.


def integrate_upstream(sha):
    integration_branch = "integrate_upstream/{sha}".format(sha=sha)
    commit_message = "Integrate: {sha} from dcos/dcos".format(sha=sha)

    execute(["git", "checkout", "-b", integration_branch])
    execute(["git", "reset", "--hard", "origin/master"])

    update_upstream_json(sha)

    execute(["git", "commit", "-am", commit_message])
    execute(["git", "push", "origin", integration_branch])
    execute(["git", "checkout", "master"])
    execute(["git", "branch", "-D", integration_branch])


if __name__ == '__main__':
    master_sha = get_latest_sha()
    if master_sha is None:
        print("Integration aborted.")
        sys.exit(1)
    integrate_upstream(master_sha)
