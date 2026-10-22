"""Validated configuration for libdecaf's generated NIF sources."""

from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CIdentifier = Annotated[str, Field(pattern=r"^[a-z][a-zA-Z0-9_]*$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Algorithm(Model):
    context: CIdentifier
    init: CIdentifier
    update: CIdentifier
    destroy: CIdentifier


class Hash(Algorithm):
    default_output_len: int = Field(gt=0)
    max_output_len: int = Field(gt=0)
    final: CIdentifier
    legacy_keccak_rate: int | None = Field(default=None, gt=0, le=200)

    @model_validator(mode="after")
    def valid_output_lengths(self) -> Self:
        if self.default_output_len > self.max_output_len:
            raise ValueError("Default hash output length must not exceed its maximum")
        return self


class XOF(Algorithm):
    output: CIdentifier


class NIF(Model):
    atoms: list[CIdentifier] = Field(default_factory=list)
    hash: dict[CIdentifier, Hash] = Field(default_factory=dict)
    xof: dict[CIdentifier, XOF] = Field(default_factory=dict)

    @field_validator("atoms")
    @classmethod
    def unique_names(cls, names: list[str]) -> list[str]:
        if len(names) != len(set(names)):
            raise ValueError("Atom names must be unique")
        return names


class Root(Model):
    nif: NIF = Field(default_factory=NIF)
