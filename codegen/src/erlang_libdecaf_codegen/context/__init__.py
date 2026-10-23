"""Template context for libdecaf code generation."""

from dataclasses import dataclass, field

from ..schema import Root
from .nif import NIF
from .functions import Function, XOFGroup, functions, xof_groups, types
from .groups import PRIME_ORDER_GROUPS, PrimeOrderGroup


@dataclass
class Context:
    _output_path: str = field(repr=False)
    schema: Root = field(repr=False)
    nif: NIF = field(init=False)

    def __post_init__(self) -> None:
        self.reset_atoms()

    def reset_atoms(self) -> None:
        self.nif = NIF(functions=functions(self.schema.nif))
        for name in self.schema.nif.atoms + list(self.schema.nif.hash) + list(self.schema.nif.xof):
            self.nif.make_atom(name)

    @property
    def types(self) -> tuple[tuple[str, str, str], ...]:
        return types(self.schema.nif)

    @property
    def opaque_type_names(self) -> set[str]:
        return {"hash_state"} | {group.state_type for group in xof_groups(self.schema.nif)}

    @property
    def xof_functions(self) -> tuple[Function, ...]:
        return tuple(function for function in self.nif.functions if function.family == "xof")

    @property
    def xof_groups(self) -> tuple[XOFGroup, ...]:
        return xof_groups(self.schema.nif)

    def hash_algorithms(self, prefix: str) -> tuple[str, ...]:
        return tuple(name for name in sorted(self.schema.nif.hash) if name.startswith(prefix))

    @property
    def prime_order_groups(self) -> tuple[PrimeOrderGroup, ...]:
        return PRIME_ORDER_GROUPS
