# Development

Build prerequisites are listed in the [README](../README.md). Rebar3 3.28.0 or
later is required for the development tools and Hex publishing. Elixir is needed
only for the benchmark scripts.
Python 3.13+, Poetry, and `just` are needed when changing generated code.

## Build and test

```sh
gmake
gmake tests
gmake ct CT_SUITES='parallel_hash rfc9861'
gmake format
gmake lint
```

`gmake lint` checks C/Erlang formatting, Eqwalizer, cross references, and Dialyzer.
ELP and erlfmt are downloaded at pinned versions on first use. For an OTP 28 ELP
installation, use `ELP_OTP_VERSION=28.5`; the default is its OTP 29.1 build.
The first full test run downloads the SHA-512, SHA-3, and legacy Keccak vector
sets. Other maintained conformance vectors are checked in under `test/`.
Common Test writes `logs/junit_report.xml`; failed tests and failed setup or
cleanup callbacks all fail the test command. CI retains the HTML and XML logs
for successful and failed runs.

GitHub CI builds and tests the latest OTP 28 and 29 releases. OTP 29 also runs
all four lint targets and builds ExDoc, with the HTML available as a workflow
artifact. A separate job checks Python formatting and generator tests using the
locked codegen dependencies. CI uses the same clang-format version as codegen.

The upstream C source is vendored under `c_deps/ed448goldilocks` and pinned in
`c_src/Makefile` to branch `features-20261025-v1.0.5`, based on tag `v1.0.5`.
If removed, it is fetched and the local empty-input patch is reapplied.

## Code generation

Generated files carry a marker at the top. Change their templates or metadata
under `codegen/`, then regenerate and commit the inputs and outputs together:

```sh
just codegen
cd codegen
poetry run pytest
```

See the [codegen workflow](https://github.com/potatosalad/erlang-libdecaf/blob/3.0.0/codegen/README.md)
for dependency locking and optional type-check fixtures.

## Documentation

```sh
gmake docs
# Equivalent direct invocation:
rebar3 ex_doc
```

Open `doc/index.html`. The README, usage guide, migration guide, changelog, and
license are included. ExDoc reads the compiled Erlang documentation and types;
source links target the `3.0.0` tag and the original `src/` files.

## Sanitizers

```sh
just sanitizers
SANITIZERS_STRESS_ITERATIONS=50000 just sanitizers
```

The Docker runner instruments ed448goldilocks and the NIF with ASan/UBSan,
runs upstream tests and all Common Test suites, and checks resource cleanup
with LeakSanitizer. Reports are retained under `logs/sanitizers/`.
On Linux with an ASan-enabled OTP installation, use `just sanitizers-native`.

## Benchmarks and packages

```sh
elixir bench/hash.exs
elixir bench/hash_highlights.exs
elixir bench/xof.exs
elixir bench/parallel_hash_stress.exs
elixir bench/parallel_xof_stress.exs
BENCH_GIB=16 elixir bench/parallel_hash_sweep.exs
sh bench/parallel_leaf_stress.sh
rebar3 hex build
```

The dedicated parallel benchmarks use 64 MiB updates. Their size sweep and
native leaf baseline help distinguish scheduling overhead from kernel limits.
The package includes the native sources, vendored dependency, and public guides;
build it locally to check its contents before publishing.

## Publishing

Use Rebar3 3.28.0 or later with the configured Hex plugin. Check the installed
version and upgrade a local Rebar3 installation when needed:

```sh
rebar3 version
rebar3 local upgrade
```

Build both package and documentation tarballs, then check the publish workflow
without uploading anything:

```sh
rebar3 hex build
rebar3 hex publish --dry-run --yes
```

Both tarballs are written under `_build/default/lib/libdecaf/hex/`. Check account
access with `rebar3 hex user whoami`; use `rebar3 hex user auth` to authenticate
when needed. After the release tag is in place, publish the package and docs with
`rebar3 hex publish`. Documentation alone can be published with
`rebar3 hex publish docs`.
