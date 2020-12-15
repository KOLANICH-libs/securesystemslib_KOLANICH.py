securesystemslib_KOLANICH.py
============================
~~[wheel (GitLab)](https://gitlab.com/KOLANICH-libs/securesystemslib_KOLANICH.py/-/jobs/artifacts/master/raw/dist/securesystemslib_KOLANICH-0.CI-py3-none-any.whl?job=build)~~
[wheel (GHA via `nightly.link`)](https://nightly.link/KOLANICH-libs/securesystemslib_KOLANICH.py/workflows/CI/master/securesystemslib_KOLANICH-0.CI-py3-none-any.whl)
~~![GitLab Build Status](https://gitlab.com/KOLANICH-libs/securesystemslib_KOLANICH.py/badges/master/pipeline.svg)~~
~~![GitLab Coverage](https://gitlab.com/KOLANICH-libs/securesystemslib_KOLANICH.py/badges/master/coverage.svg)~~
[![GitHub Actions](https://github.com/KOLANICH-libs/securesystemslib_KOLANICH.py/workflows/CI/badge.svg)](https://github.com/KOLANICH-libs/securesystemslib_KOLANICH.py/actions/)
[![Libraries.io Status](https://img.shields.io/librariesio/github/KOLANICH-libs/securesystemslib_KOLANICH.py.svg)](https://libraries.io/github/KOLANICH-libs/securesystemslib_KOLANICH.py)
[![Code style: antiflash](https://img.shields.io/badge/code%20style-antiflash-FFF.svg)](https://github.com/KOLANICH-tools/antiflash.py)

My additions to [`securesystemslib`](https://github.com/secure-systems-lab/securesystemslib).

* https://github.com/secure-systems-lab/securesystemslib/pull/452 - implements a method to generate a `securesystemslib` `dict` for a `ed25519` key - used internally.
* https://github.com/secure-systems-lab/securesystemslib/pull/451 - implements import of SSH keys. `from securesystemslib_KOLANICH.convert.ssh import import_ssh_key`
* https://github.com/secure-systems-lab/securesystemslib/pull/453 - monkey-patches inconsistent keyids for ECDSA keys - just `import securesystemslib_KOLANICH`

The most of this lib is licensed under `Unlicense`, but some files with portions copied from `securesystemslib` are licensed under `MIT`.
