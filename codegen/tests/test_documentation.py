from pathlib import Path

import pytest

from erlang_libdecaf_codegen.code_generator import CodeGenerator, TOKEN, sign_source
from erlang_libdecaf_codegen.documentation import ErlangExamples


def documentation_generator(tmp_path, templates):
    config = tmp_path / "config.yaml"
    config.write_text("nif: {}\n")
    for stage in ("templates0", "templates1", "templates2"):
        (tmp_path / stage).mkdir()
    for name, source in templates.items():
        (tmp_path / "templates2" / name).write_text(source)
    return CodeGenerator(
        str(config),
        str(tmp_path / "output"),
        *(str(tmp_path / stage) for stage in ("templates0", "templates1", "templates2")),
    )


def test_documentation_inserts_runtime_values_and_checks_complete_examples(tmp_path, monkeypatch):
    codegen = documentation_generator(
        tmp_path,
        {"README.md.j2": '```erlang\n~J< erlang("binary:encode_hex(<<1, 2>>)") >. = binary:encode_hex(<<1, 2>>).\n```\n'},
    )
    requests = []

    def run(self, batch):
        requests.extend(batch)
        return ['<<"0102">>'] if batch[0]["format"] == "term" else ["ok"]

    monkeypatch.setattr(ErlangExamples, "run", run)
    codegen.render_docs()
    output = Path(codegen.output_path, "README.md").read_bytes()
    assert output.startswith(b"<!--\nDO NOT EDIT:")
    assert b"@generated SignedSource<<" in output and TOKEN.encode() not in output
    assert b'<<"0102">> = binary:encode_hex(<<1, 2>>).' in output
    assert requests[-1] == {"source": '<<"0102">> = binary:encode_hex(<<1, 2>>).\n', "format": "check"}
    assert sign_source(output) == output
    codegen.render_docs(check=True)
    assert Path(codegen.output_path, "README.md").read_bytes() == output


def test_failed_example_preserves_all_existing_documentation(tmp_path, monkeypatch):
    codegen = documentation_generator(
        tmp_path,
        {"A.md.j2": "New content\n", "B.md.j2": "```erlang\nfalse = true.\n```\n"},
    )
    output = Path(codegen.output_path)
    output.mkdir()
    (output / "A.md").write_text("Existing A\n")
    (output / "B.md").write_text("Existing B\n")

    def run(self, batch):
        raise ValueError("badmatch")

    monkeypatch.setattr(ErlangExamples, "run", run)
    with pytest.raises(ValueError, match="badmatch"):
        codegen.render_docs()
    assert (output / "A.md").read_text() == "Existing A\n"
    assert (output / "B.md").read_text() == "Existing B\n"


def test_documentation_check_detects_stale_content_without_writing(tmp_path):
    codegen = documentation_generator(tmp_path, {"README.md.j2": "Current\n"})
    codegen.render_docs()
    output = Path(codegen.output_path, "README.md")
    output.write_text("Stale\n")
    with pytest.raises(ValueError, match="out of date"):
        codegen.render_docs(check=True)
    assert output.read_text() == "Stale\n"


def test_documentation_requires_built_library_for_runtime_examples(tmp_path):
    examples = ErlangExamples(tmp_path / "missing-ebin")
    with pytest.raises(ValueError, match="run gmake first"):
        examples.run([{"source": "ok", "format": "term"}])
