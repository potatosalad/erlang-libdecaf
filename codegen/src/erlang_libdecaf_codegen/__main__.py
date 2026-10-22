"""Command-line interface for codegen."""

import click
import json
from pathlib import Path

from . import CodeGenerator, Root


@click.group()
def main():
    """Command-line utility for codegen and schema validation."""
    pass


@main.command("generate")
@click.argument("config_file", type=click.Path(exists=True))
@click.argument("output_path", type=click.Path())
@click.argument("templates0_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.argument("templates1_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
def generate(config_file: str, output_path: str, templates0_path: str, templates1_path: str):
    """Generate C and Erlang code from YAML configuration using Jinja2."""

    code_generator: CodeGenerator = CodeGenerator(config_file, output_path, templates0_path, templates1_path)

    code_generator.render()


@main.command("json-schema")
@click.argument("output_path", type=click.Path())
def json_schema(output_path: str):
    """Generate a JSON schema for the configuration file."""

    Path(output_path).write_text(json.dumps(Root.model_json_schema(), indent=2))
    print(f"Wrote JSON schema to: {output_path}")


@main.command("sign")
@click.argument("config_file", type=click.Path(exists=True))
@click.argument("output_path", type=click.Path())
@click.argument("templates0_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.argument("templates1_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
def sign(config_file: str, output_path: str, templates0_path: str, templates1_path: str):
    """Sign C and Erlang code from YAML configuration using Jinja2."""

    code_generator: CodeGenerator = CodeGenerator(config_file, output_path, templates0_path, templates1_path)

    code_generator.sign()


if __name__ == "__main__":
    main()  # type: ignore
