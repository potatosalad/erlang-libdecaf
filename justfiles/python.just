export POETRY_VIRTUALENVS_IN_PROJECT := "true"

[working-directory: justfile_directory() / 'codegen']
poetry-install:
    poetry install --no-interaction

[working-directory: justfile_directory() / 'codegen']
poetry-lock:
    poetry lock --regenerate --no-interaction
    poetry install --no-interaction
    poetry export --no-interaction --without-hashes --without-urls --format=requirements.txt --output=requirements.txt
