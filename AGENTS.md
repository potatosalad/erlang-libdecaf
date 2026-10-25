# Maintenance

- APIs: `src/`; native components: `c_src/nif/`; tests: `test/`. CI targets OTP 28/29.
- Generated files: edit `codegen/` inputs, run `just codegen`, commit inputs and outputs. See `codegen/README.md`.
- Python dependencies: edit `codegen/pyproject.toml`, run `just lock`, include `poetry.lock` and `requirements.txt`.
- Run `gmake format`, `gmake tests`, `gmake lint`, and `gmake docs`; generator checks: `cd codegen && poetry run pytest`.
- Erlang: multiline exports, named specs, type exports after definitions; preserve module metadata. Keep generated functions/types sorted.
- Native components own resources. Hash/XOF resources stay distinct; updates return immutable states. Yield long work and release retained state on every exit.
- Use `decaf_bzero` for sensitive memory; check upstream alignment requirements. Validate crypto with published vectors and `just sanitizers`.
- Vendored ed448goldilocks is pinned in `c_src/Makefile`; include native sources in package checks.
- Release version: `Makefile` and `src/libdecaf.app.src`; update README, changelog, and `ex_doc.config` source links together. Check `rebar3 hex build` contents.
- Make incremental signed commits (`git commit -S`).
