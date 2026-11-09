# Feedback task starting environment

Upstream: https://github.com/jpadilla/pyjwt
Upstream commit: `16231abfd1d8eab4953e8779b3017b859c88565e`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_jwks_client.py tests/test_api_jwk.py
```

Observed baseline (2026-11-09): `72 passed, 3 skipped in 4.75s`
Whole-command wall time: 6.051 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
