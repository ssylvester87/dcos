# Mesosphere Enterprise DC/OS

Mesosphere Enterprise DC/OS derived from [Open DC/OS](https://github.com/dcos/dcos)

# Major pieces

 - `config/dcos-release.config.yaml`: `release` tool configuration (where to upload, what urls people will access it at)
 - `packages/upstream.json`: Defines the package repository to grab from
 - `packages/*` All other files are exactly the same as in `dcos/dcos`. Definitions of packages, as well as definitions of what goes into various "distributions". If any variants of a package are in this directory, it entirely replaces the upstream packages.
  - `gen_extra/async_server.py`: Can arbitrarily modify the DC/OS web installer app. See `extend_app()` for examples.
  - `gen_extra/calc.py`: Adds / modifies the upstream repository's calc. Everything in "entry" overrides all previous ways (both defaults and must) to set the value for that configuration. The loaded bit is `entry`.
  - `gen_extra/dcos-config.yaml`: Adds additional files which will be written to hosts. NOTE: Do not overwrite / use the same name as a file already in `gen/dcos-config.yaml` as that will result in undefined behavior (and not hard error :/)
  - `gen_extra/`: dcos-config.yaml was pulled out as a special case, but any yaml config (cloud-config.yaml, dcos-metadata.yaml, dcos-services.yaml) can have additional files / chunks added to it by making a file of the same name in the gen_extra folder.
  - `util/`: Simple scripts to help with CI (checkout the same commit of dcos/dcos as referenced by upstream.json then use that to build this)

# Testing locally
`tox`

# Building Remotely (in Team City)
Master builds:
```
https://downloads.mesosphere.com/dcos-enterprise/testing/master/dcos_generate_config.ee.sh
```

PR Builds:
```
https://downloads.mesosphere.com/dcos-enterprise/testing/pull/<PULL_NUMBER>/dcos_generate_config.ee.sh
```

# Building locally

1. Create a dcos-release.config.yaml as specified in https://github.com/dcos/dcos#setup-a-build-environment
1. Do one of the following

  a. *Use the local build script*
    - Run `./util/build_local.sh`
    - _NOTE_: This guarantees what is used to build matches what is in upstream.json. All upstream changes must be committed and pushed somewhere they can be grabbed by `util/fetch_dcos.py` which only understands really simple git clones.

  b. *Use a existing https://github.com/dcos/dcos clone*
    - Run `prep_local` in the https://github.com/dcos/dcos checkout inside of a Python virtual environment to install https://github.com/dcos/dcos to it
    - cd into the dcos-enterprise checkout and run `release create` to do the build
    - _NOTE_: The dcos/dcos which gets bundled inside the build is defined by the `upstream.json`. So the dcos/dcos you build with is not necessarily the one which will end up inside of dcos_generate_config.sh

  c. *Use the CI scripts*
    - Run `./util/build.py`
    - _NOTE_: This guarantees the checkout of dcos/dcos matches what is in upstream.json, but it hasn't been made as user friendly (it's intended to run in the one very specific CI environment), so you'll have to set things like TEAMCITY_BRANCH. It also requires both AWS Prod and AWS Dev credentials to use the dcos-release.config.yaml. USE WITH CAUTION. You can take out the shipping DC/OS.

# Contributing

All PRs are contributed through pull requests, these must pass basic sanity checks.
