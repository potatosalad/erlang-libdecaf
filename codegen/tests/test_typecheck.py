"""Opt-in checks against the actual Erlang static analyzers, including negative examples."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


def run(*arguments, cwd):
    return subprocess.run(arguments, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    if os.environ.get("LIBDECAF_TYPECHECK") != "1":
        pytest.skip("Set LIBDECAF_TYPECHECK=1 to run Dialyzer and Eqwalizer")
    root = Path(__file__).resolve().parents[2]
    dialyzer = shutil.which("dialyzer")
    elp = root / "elp"
    assert dialyzer is not None, "Dialyzer must be installed"
    assert elp.is_file(), "Run gmake elp before the static-check regressions"
    directory = tmp_path_factory.mktemp("hash-typecheck")
    source = directory / "src"
    source.mkdir()
    for module in ("libdecaf", "libdecaf_nif"):
        shutil.copy(root / "src" / f"{module}.erl", source)
    for fixture in Path(__file__).with_name("typecheck").glob("*.erl"):
        shutil.copy(fixture, source)
    build_info = directory / "build-info.json"
    build_info.write_text(
        json.dumps(
            {
                "apps": [
                    {
                        "name": "hash_typecheck",
                        "dir": str(directory),
                        "src_dirs": ["src"],
                        "extra_src_dirs": [],
                        "include_dirs": [],
                        "macros": {},
                    }
                ],
                "deps": [],
            }
        )
    )
    return directory, dialyzer, str(elp), str(build_info)


def test_dialyzer_rejects_wrong_groups_and_parameters(project):
    directory, dialyzer, _, _ = project
    configured_plt = os.environ.get("LIBDECAF_TYPECHECK_PLT")
    plt = Path(configured_plt).resolve() if configured_plt else directory / "otp.plt"
    if not configured_plt:
        built = run(
            dialyzer,
            "--build_plt",
            "--apps",
            "erts",
            "kernel",
            "stdlib",
            "compiler",
            "crypto",
            "syntax_tools",
            "parsetools",
            "--output_plt",
            str(plt),
            cwd=directory,
        )
        assert built.returncode == 0, built.stdout
    base = (dialyzer, "--plt", str(plt), "--no_check_plt", "--src", "src/libdecaf_nif.erl", "src/libdecaf.erl")
    valid = run(*base, "src/hash_valid.erl", cwd=directory)
    assert valid.returncode == 0, valid.stdout
    invalid = run(*base, "src/hash_invalid.erl", cwd=directory)
    assert invalid.returncode == 2, invalid.stdout
    for function in ("hash_update", "hash_init", "xof_absorb", "turboshake128_xof_init", "kt128_xof_init"):
        assert function in invalid.stdout, invalid.stdout
    assert "libdecaf:hash_update" in invalid.stdout, invalid.stdout
    assert "breaks the contract" in invalid.stdout, invalid.stdout


def test_eqwalizer_rejects_wrong_algorithms_and_parameters(project):
    directory, _, elp, build_info = project
    base = (elp, "eqwalize", "--project", build_info, "--no-connect", "--bail-on-error", "--format", "json")
    valid = run(*base, "libdecaf_nif", "libdecaf", "hash_valid", cwd=directory)
    assert valid.returncode == 0, valid.stdout
    invalid = run(*base, "hash_invalid", cwd=directory)
    assert invalid.returncode != 0, invalid.stdout
    diagnostics = [json.loads(line) for line in invalid.stdout.splitlines() if line.startswith("{")]
    descriptions = "\n".join(item["description"] for item in diagnostics)
    assert "integer()" in descriptions, invalid.stdout
    assert "kmacxof128" in descriptions and "kmac128" in descriptions, invalid.stdout
    assert "shake128" in descriptions, invalid.stdout
