from types import SimpleNamespace
from pathlib import Path
import re

import pytest
import yaml
from pydantic import ValidationError

from erlang_libdecaf_codegen.code_generator import TOKEN, CodeGenerator, StageTarget
from erlang_libdecaf_codegen.schema import Root
from erlang_libdecaf_codegen.context.functions import functions


def test_sign_is_idempotent(tmp_path):
    stage = SimpleNamespace(codegen=SimpleNamespace(output_path=str(tmp_path)))
    target = StageTarget(stage=stage, template_name="generated.c.j2", output_name="generated.c")
    unsigned = f"// @generated {TOKEN}\nint generated(void) {{ return 0; }}\n".encode("utf-8")
    output_file = tmp_path / "generated.c"
    output_file.write_bytes(unsigned)

    target.sign()
    signed_once = output_file.read_bytes()
    target.sign()

    assert output_file.read_bytes() == signed_once
    assert TOKEN.encode("utf-8") not in signed_once


def generator(tmp_path, source):
    config = tmp_path / "config.yaml"
    config.write_text("nif:\n  atoms: [configured]\n")
    templates0 = tmp_path / "templates0"
    templates0.mkdir()
    output = tmp_path / "output"
    nif = output / "c_src" / "nif"
    nif.mkdir(parents=True)
    (nif / "input.c").write_text(source)
    templates1 = Path(__file__).resolve().parents[1] / "templates1"
    return CodeGenerator(str(config), str(output), str(templates0), str(templates1)), nif, templates0


def atom_names(nif):
    header = (nif / "libdecaf_nif_atoms.h").read_text()
    return re.findall(r"ERL_NIF_TERM ATOM_(\w+);", header)


def test_atom_discovery_ignores_comments_literals_and_macro_parameters(tmp_path):
    codegen, nif, templates0 = generator(
        tmp_path,
        r"""
#define ATOM(name) atoms->ATOM_##name
#define RETURN_ERROR(env) ATOM(error)
ATOM(zebra); ATOM( alpha ); ATOM(alpha);
ATOM(
  multiline
);
// ATOM(line_comment)
/* ATOM(block_comment) */
"ATOM(string_literal)";
'ATOM(character_literal)';
MAKE_ATOM(not_a_reference);
""",
    )
    template = templates0 / "c_src" / "nif" / "generated.c.j2"
    template.parent.mkdir(parents=True)
    template.write_text("ATOM(stage_zero);\n")
    # Include the new stage-zero template in discovery.
    codegen = CodeGenerator(codegen.config_file, codegen.output_path, str(templates0), codegen.templates1_path)
    codegen.render()
    codegen.sign()

    assert atom_names(nif) == ["alpha", "configured", "error", "multiline", "stage_zero", "zebra"]
    source = (nif / "libdecaf_nif_atoms.c").read_text()
    assert 'libdecaf_nif_atom_table->ATOM_alpha = enif_make_atom(env, "alpha");' in source
    assert "MAKE_ATOM" not in source
    assert not (Path(codegen.output_path) / "apps").exists()


def test_regeneration_is_stable_and_removes_stale_atoms(tmp_path):
    codegen, nif, _ = generator(tmp_path, "ATOM(old_atom);\n")
    codegen.render()
    codegen.sign()
    generated = [nif / "libdecaf_nif_atoms.c", nif / "libdecaf_nif_atoms.h"]
    first = [path.read_bytes() for path in generated]
    codegen.render()
    codegen.sign()
    assert [path.read_bytes() for path in generated] == first

    (nif / "input.c").write_text("ATOM(new_atom);\n")
    codegen.render()
    codegen.sign()
    assert atom_names(nif) == ["configured", "new_atom"]


@pytest.mark.parametrize("field", ["atoms", "hash", "xof"])
@pytest.mark.parametrize("names", [["not-an-identifier"], ["same", "same"]])
def test_invalid_name_configuration_is_rejected(field, names):
    with pytest.raises(ValidationError):
        Root.model_validate({"nif": {field: names}})


def test_algorithm_names_seed_atoms_without_literal_references(tmp_path):
    codegen, nif, _ = generator(tmp_path, "")
    Path(codegen.config_file).write_text("nif:\n  hash: [sha2_512]\n  xof: [shake256]\n")
    codegen = CodeGenerator(codegen.config_file, codegen.output_path, codegen.templates0_path, codegen.templates1_path)
    codegen.render()
    assert atom_names(nif) == ["sha2_512", "shake256"]


def test_unadapted_reference_configuration_is_rejected():
    with pytest.raises(ValidationError):
        Root.model_validate({"channel": {"stats": []}})


def test_erlang_templates_use_erlang_delimiters_and_signed_headers(tmp_path):
    codegen, _, templates0 = generator(tmp_path, "")
    template = templates0 / "src" / "example.erl.j2"
    template.parent.mkdir()
    template.write_text("-module(example).\n~J{ for name in ctx.schema.nif.atoms }.\n~J< name >.() -> ok.\n~J{ endfor }.\n")
    codegen = CodeGenerator(codegen.config_file, codegen.output_path, str(templates0), codegen.templates1_path)
    codegen.render()
    codegen.sign()
    output = Path(codegen.output_path, "src", "example.erl").read_text()
    assert output.startswith("%%% % DO NOT EDIT:")
    assert "%%% % @generated SignedSource<<" in output
    assert "configured() -> ok." in output
    assert "~J" not in output
    assert TOKEN not in output


def test_erlang_native_bindings_match_the_c_registration_table():
    root = Path(__file__).resolve().parents[2]
    schema = Root.model_validate(yaml.safe_load((root / "codegen/config.yaml").read_text()))
    source = (root / "c_src/nif/libdecaf_nif.c").read_text()
    native = {(name, int(arity)) for name, arity in re.findall(r'\{\s*"([a-z0-9_]+)"\s*,\s*(\d+)\s*,\s*libdecaf_nif_', source)}
    group_source = (root / "c_src/nif/groups.h").read_text()
    group_operations = re.findall(r'#Name\s*"(_[a-z0-9_]+)"\s*,\s*(\d+)', group_source)
    for group in re.findall(r"LIBDECAF_GROUP_NIFS\((\w+)\)", source):
        native.update((group + operation, int(arity)) for operation, arity in group_operations)
    generated = {(function.name, function.arity) for function in functions(schema.nif)}
    assert generated == native
