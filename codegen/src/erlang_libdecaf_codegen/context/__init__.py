"""Template context for libdecaf code generation."""

from dataclasses import dataclass, field

from ..schema import Root
from .nif import NIF
from .functions import functions, xof_groups, types
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
        names = (
            self.schema.nif.atoms
            + list(self.schema.nif.hash)
            + list(self.schema.nif.kmac)
            + list(self.schema.nif.hopmac)
            + list(self.schema.nif.xof)
        )
        for family in self.derived_families:
            names += list(getattr(self.schema.nif, family))
        for name in names:
            self.nif.make_atom(name)

    @property
    def types(self) -> tuple[tuple[str, str, str], ...]:
        return types(self.schema.nif)

    @property
    def opaque_type_names(self) -> set[str]:
        return {
            "hash_state",
            "xof_state",
            "ed25519ph_sign_state",
            "ed25519ph_verify_state",
            "ed448ph_sign_state",
            "ed448ph_verify_state",
        }

    @property
    def crypto_families(self):
        from .crypto import families

        return families(self.schema.nif)

    def crypto_profiles(self, family):
        from .crypto import profiles

        return profiles(self.schema.nif, family)

    def crypto_doc(self, function):
        from .crypto import public_doc

        return public_doc(self.schema.nif, function)

    def crypto_algorithms(self, family=None):
        from .crypto import native_algorithms

        return tuple(a for a in native_algorithms(self.schema.nif) if family is None or a.family.name == family.name)

    @property
    def crypto_max_arity(self):
        return max(f.arity for f in self.crypto_functions)

    @property
    def public_crypto_type_names(self):
        from .crypto import api_types

        return {name for name, _, _ in api_types(self.schema.nif)}

    @property
    def public_crypto_functions(self):
        from .crypto import public_functions

        return public_functions(self.schema.nif)

    @property
    def public_types(self):
        from .public_key import Type, types as public_key_types

        aliases = (
            Type(name, f"libdecaf_nif:{name}()", doc)
            for name, _, doc in self.types
            if name in self.public_crypto_type_names
        )
        return tuple(sorted((*aliases, *public_key_types()), key=lambda item: item.name))

    @property
    def public_key_functions(self):
        from .public_key import functions

        return functions()

    def public_key_function(self, name, arity):
        return next(f for f in self.public_key_functions if (f.name, f.arity) == (name, arity))

    @property
    def agreement_curves(self):
        from .public_key import AGREEMENT_CURVES

        return AGREEMENT_CURVES

    @property
    def signature_curves(self):
        from .public_key import SIGNATURE_CURVES

        return SIGNATURE_CURVES

    @property
    def signature_variants(self):
        from .public_key import VARIANTS

        return VARIANTS

    @property
    def crypto_functions(self):
        return tuple(f for f in self.nif.functions if f.family in ("hash", "xof"))

    @property
    def xof_groups(self):
        return xof_groups(self.schema.nif)

    @property
    def derived_families(self):
        return ("parallelhash", "tuplehash")

    def hash_algorithms(self, prefix):
        return tuple(n for n in sorted(self.schema.nif.hash) if n.startswith(prefix))

    @property
    def tuak_functions(self):
        return tuple(f for f in self.nif.functions if f.family == "tuak")

    @property
    def tuak_operations(self):
        from .tuak import operations

        return operations()

    @property
    def tuak_options(self):
        from .tuak import OPTIONS

        return OPTIONS

    @property
    def tuak_types(self):
        from .tuak import types

        return tuple(
            (name.removeprefix("tuak_"), definition.replace("tuak_", ""), doc)
            for name, definition, doc in types(self.schema.nif.tuak)
        )

    @property
    def tuak_public_functions(self):
        from .tuak import public_functions

        return public_functions()

    @property
    def prime_order_groups(self) -> tuple[PrimeOrderGroup, ...]:
        return PRIME_ORDER_GROUPS
