"""Validated configuration for libdecaf's generated NIF sources."""

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CIdentifier = Annotated[str, Field(pattern=r"^[a-z][a-zA-Z0-9_]*$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Hash(Model):
    default_output_len: int = Field(gt=0)
    max_output_len: int = Field(gt=0)
    legacy_keccak_rate: int | None = Field(default=None, gt=0, le=200)

    @model_validator(mode="after")
    def valid_output_lengths(self) -> Self:
        if self.default_output_len > self.max_output_len:
            raise ValueError("Default hash output length must not exceed its maximum")
        return self


class XOF(Model):
    default_output_len: int = Field(gt=0)
    group: CIdentifier
    legacy_keccak_rate: int | None = Field(default=None, gt=0, lt=200)
    cshake_rate: int | None = Field(default=None, gt=0, lt=200)
    turbo_rate: int | None = Field(default=None, gt=0, lt=200)
    kt_rate: Literal[136, 168] | None = None
    sp800185: Literal["kmac", "tuplehash", "parallelhash"] | None = None
    sp800185_rate: Literal[136, 168] | None = None

    @model_validator(mode="after")
    def valid_padding(self) -> Self:
        if (
            sum(
                rate is not None
                for rate in (self.legacy_keccak_rate, self.cshake_rate, self.turbo_rate, self.kt_rate, self.sp800185_rate)
            )
            > 1
        ):
            raise ValueError("An XOF can select only one sponge initialization mode")
        if (self.sp800185 is None) != (self.sp800185_rate is None):
            raise ValueError("SP 800-185 XOFs require a construction and sponge rate")
        return self


class DerivedSponge(Model):
    rate: Literal[136, 168]


class TUAK(Model):
    default_mac_length: Literal[8, 16, 32] = 8
    default_res_length: Literal[4, 8, 16, 32] = 8
    default_ck_length: Literal[16, 32] = 16
    default_ik_length: Literal[16, 32] = 16
    default_iterations: int = Field(default=1, gt=0, le=4294967295)


class NIF(Model):
    atoms: list[CIdentifier] = Field(default_factory=list)
    hash: dict[CIdentifier, Hash] = Field(default_factory=dict)
    hopmac: dict[CIdentifier, DerivedSponge] = Field(default_factory=dict)
    kmac: dict[CIdentifier, DerivedSponge] = Field(default_factory=dict)
    parallelhash: dict[CIdentifier, DerivedSponge] = Field(default_factory=dict)
    tuplehash: dict[CIdentifier, DerivedSponge] = Field(default_factory=dict)
    tuak: TUAK = Field(default_factory=TUAK)
    xof: dict[CIdentifier, XOF] = Field(default_factory=dict)

    @model_validator(mode="after")
    def consistent_groups(self) -> Self:
        modes = {}
        for profile in self.xof.values():
            mode = (
                profile.cshake_rate is not None,
                profile.turbo_rate is not None,
                profile.kt_rate is not None,
                profile.sp800185,
            )
            if profile.group in modes and modes[profile.group] != mode:
                raise ValueError("Algorithms in an API group must accept the same parameters")
            modes[profile.group] = mode
        return self

    @field_validator("atoms")
    @classmethod
    def unique_names(cls, names: list[str]) -> list[str]:
        if len(names) != len(set(names)):
            raise ValueError("Atom names must be unique")
        return names


class Root(Model):
    nif: NIF = Field(default_factory=NIF)
