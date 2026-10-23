"""Native metadata shared by prime-order group templates and Erlang bindings."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PrimeOrderGroup:
    name: str
    title: str
    directory: str
    bits: int
    encoding_bytes: int

    @property
    def upstream(self) -> str:
        return f"decaf_{self.bits}"

    @property
    def point_bytes(self) -> str:
        return f"DECAF_{self.bits}_SER_BYTES"

    @property
    def scalar_bytes(self) -> str:
        return f"DECAF_{self.bits}_SCALAR_BYTES"


PRIME_ORDER_GROUPS = (
    PrimeOrderGroup("ristretto255", "Ristretto255", "curve25519", 255, 32),
    PrimeOrderGroup("decaf448", "Decaf448", "curve448", 448, 56),
)
