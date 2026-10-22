"""Validated configuration for libdecaf's generated NIF sources."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

CIdentifier = Annotated[str, Field(pattern=r"^[a-z][a-zA-Z0-9_]*$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NIF(Model):
    atoms: list[CIdentifier] = Field(default_factory=list)

    @field_validator("atoms")
    @classmethod
    def unique_atoms(cls, atoms: list[str]) -> list[str]:
        if len(atoms) != len(set(atoms)):
            raise ValueError("Atom names must be unique")
        return atoms


class Root(Model):
    nif: NIF = Field(default_factory=NIF)
