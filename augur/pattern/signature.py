"""A deliberately narrow C function signature model: just enough to
decide whether every parameter is a primitive/pointer-to-primitive type
Augur knows how to synthesize adversarial values for. Anything it can't
confidently classify is treated as NOT simple -- silence over a wrong
guess."""
from __future__ import annotations

import re

_PRIMITIVE_BASE_TYPES = {
    "void", "char", "int", "short", "long", "float", "double", "bool",
    "size_t", "ssize_t", "unsigned", "signed",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
}
_QUALIFIERS = {"const", "static", "inline", "register", "volatile"}


class Parameter:
    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.pointer_depth = self.raw.count("*")
        tokens = self.raw.replace("*", " ").split()
        self.name = tokens[-1] if tokens else ""
        self.type_tokens = [t for t in tokens[:-1] if t not in _QUALIFIERS]

    def is_primitive(self) -> bool:
        """True only for a non-pointer primitive scalar (e.g. `int`,
        `size_t`) -- Augur only knows how to synthesize adversarial
        values for scalars and char* strings (see is_string_like), not
        for "pointer to a single int/struct/whatever", whose meaning
        (out-param? array? optional?) it has no way to infer."""
        if self.pointer_depth != 0:
            return False
        if not self.type_tokens:
            return False
        if any(t in ("struct", "union", "enum") for t in self.type_tokens):
            return False
        return all(t in _PRIMITIVE_BASE_TYPES for t in self.type_tokens)

    def is_string_like(self) -> bool:
        """char* / const char* -- the one pointer shape Augur can safely
        synthesize adversarial values for (short strings, missing
        terminators) without knowing what the buffer is supposed to mean."""
        return "char" in self.type_tokens and self.pointer_depth >= 1

    def is_integer_like(self) -> bool:
        return self.is_primitive() and "char" not in self.type_tokens and "void" not in self.type_tokens


class FunctionSignature:
    def __init__(self, return_type: str, name: str, parameters: list[Parameter]):
        self.return_type = return_type.strip()
        self.name = name
        self.parameters = parameters

    def is_simple(self) -> bool:
        """True only if every parameter is a type Augur can synthesize
        adversarial input for. Custom structs, function pointers, or
        anything unparseable -> False, meaning "needs manual review,"
        never a silent wrong guess."""
        if not self.parameters:
            return False
        return all(p.is_primitive() or p.is_string_like() for p in self.parameters)

    @classmethod
    def parse(cls, return_type: str, name: str, params_text: str) -> "FunctionSignature | None":
        params_text = params_text.strip()
        if params_text in ("", "void"):
            return cls(return_type, name, [])
        if "(" in params_text:  # function-pointer parameter -- out of scope
            return None
        raw_params = [p.strip() for p in params_text.split(",") if p.strip()]
        parameters = [Parameter(p) for p in raw_params]
        if any(not p.name for p in parameters):
            return None
        return cls(return_type, name, parameters)
