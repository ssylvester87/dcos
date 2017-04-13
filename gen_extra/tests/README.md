# `gen_extra` tests

`gen_extra` isn't a proper python package and only particular files are loaded
in open DC/OS `gen` package.

`calc.py` is [loaded](https://github.com/dcos/dcos/blob/3b0654ef58533765fb4536808b410862c8201a3c/gen/__init__.py#L455)
when the configuration generator runs, resolves and validates configuration.

`async_server.py` is loaded when the `web` installer is started.

## Tests environment

`gen_extra` isn't a standalone python package and it requires dependencies
from open DC/OS version. To setup environment where tests could be executed
run `env.sh` script from root folder of `dcos-enterprise` directory, i.e.:

```
./gen_extra/tests/env.sh
```

This script will fetch open DC/OS defined in `packages/upstream.json`, it will
create new `pyvenv` and run script from open DC/OS to install all required
packages.

Once installation is done tests can be started with `pytest` command.

```sh
pytest -vv -s gen_extra/tests/
```