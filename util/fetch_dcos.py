#!/usr/bin/env python3.4

import json
import os.path
from subprocess import check_call

upstream = json.load(open("packages/upstream.json"))
commit = upstream["ref"]
repo = upstream["git"]

# NOTE: This logic is taken out of the pkgpanda git src_fetcher
if not os.path.exists("ext/upstream"):
    check_call(["git", "clone", repo, "ext/upstream"])
else:
    check_call([
        "git",
        "--git-dir", "ext/upstream/.git",
        "--work-tree", "ext/upstream",
        "remote",
        "set-url",
        "origin",
        repo])
    check_call([
        "git",
        "--git-dir", "ext/upstream/.git",
        "--work-tree", "ext/upstream",
        "remote",
        "update",
        "origin"])

check_call([
    "git",
    "--git-dir", "ext/upstream/.git",
    "--work-tree", "ext/upstream",
    "checkout",
    "-f",
    "-q",
    commit])
