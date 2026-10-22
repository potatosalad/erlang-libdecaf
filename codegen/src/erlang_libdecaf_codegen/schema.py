"""Validated configuration for libdecaf's generated NIF sources."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

CIdentifier = Annotated[str, Field(pattern=r"^[a-z][a-zA-Z0-9_]*$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NIF(Model):
    atoms: list[CIdentifier] = Field(default_factory=list)
    hash: list[CIdentifier] = Field(default_factory=list)
    xof: list[CIdentifier] = Field(default_factory=list)

    @field_validator("atoms", "hash", "xof")
    @classmethod
    def unique_names(cls, names: list[str]) -> list[str]:
        if len(names) != len(set(names)):
            raise ValueError("Names must be unique within each list")
        return names


class Root(Model):
    nif: NIF = Field(default_factory=NIF)
