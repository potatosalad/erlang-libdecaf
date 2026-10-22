"""Stable, deduplicated NIF atom definitions."""

from dataclasses import dataclass, field

from .functions import Function


@dataclass(frozen=True, order=True)
class Atom:
    name: str


@dataclass
class NIF:
    functions: tuple[Function, ...] = ()
    atoms_dict: dict[str, Atom] = field(default_factory=dict)

    @property
    def atoms_list(self) -> list[Atom]:
        return sorted(self.atoms_dict.values())

    def make_atom(self, name: str) -> Atom:
        if name not in self.atoms_dict:
            self.atoms_dict[name] = Atom(name)
        return self.atoms_dict[name]
