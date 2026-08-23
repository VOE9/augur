"""Mechanically derives the exact literal prefix bytes a function's own
internal search logic expects, by tracing a `snprintf(var, len, "fmt",
args...)` call whose result variable is later used as the needle in a
`strstr()` call against the tainted string parameter.

This exists to remove the one remaining piece of human-supplied
knowledge Augur's harness still needed: a realistic example value for
the string parameter. For this narrow, real pattern -- a fixed format
string built from the function's own other (already-known) parameters,
then searched for directly in the tainted input -- the required prefix
isn't a guess, it's readable straight out of the function's own source."""
from __future__ import annotations

import re
from dataclasses import dataclass

_SNPRINTF_RE = re.compile(r'\bsn?printf\s*\(\s*(\w+)\s*,\s*\d+\s*,\s*"((?:[^"\\]|\\.)*)"\s*(?:,\s*([^)]*))?\)')
_STRSTR_RE = re.compile(r"\bstrstr\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)")

# Deliberately just the two conversions the real target pattern uses.
# Anything else in the format string -> refuse rather than render wrong.
_SUPPORTED_CONVERSIONS = {"%d", "%s"}


@dataclass(frozen=True)
class DerivedPrefix:
    literal_bytes: str
    needle_variable: str


class FormatStringPrefixDeriver:
    def derive(self, function_text: str, string_param_name: str, other_param_values: dict[str, str]) -> DerivedPrefix | None:
        search_call = self._find_search_call(function_text, string_param_name)
        if search_call is None:
            return None
        haystack_var, needle_var, search_pos = search_call

        snprintf_match = None
        for m in _SNPRINTF_RE.finditer(function_text):
            if m.group(1) == needle_var and m.start() < search_pos:
                snprintf_match = m  # keep the last one before the search call

        if snprintf_match is None:
            return None

        fmt, args_text = snprintf_match.group(2), snprintf_match.group(3) or ""
        args = [a.strip() for a in args_text.split(",") if a.strip()]
        rendered = self._render(fmt, args, other_param_values)
        if rendered is None:
            return None
        return DerivedPrefix(literal_bytes=rendered, needle_variable=needle_var)

    @staticmethod
    def _find_search_call(function_text: str, string_param_name: str) -> tuple[str, str, int] | None:
        for m in _STRSTR_RE.finditer(function_text):
            haystack, needle = m.group(1), m.group(2)
            if haystack == string_param_name:
                return haystack, needle, m.start()
        return None

    @staticmethod
    def _render(fmt: str, args: list[str], values: dict[str, str]) -> str | None:
        conversions = re.findall(r"%[a-zA-Z]", fmt)
        if not conversions or any(c not in _SUPPORTED_CONVERSIONS for c in conversions):
            return None
        if len(conversions) > len(args):
            return None

        fmt = fmt.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\\\", "\\")

        out, arg_i = [], 0
        i = 0
        while i < len(fmt):
            if fmt[i] == "%" and i + 1 < len(fmt) and f"%{fmt[i+1]}" in _SUPPORTED_CONVERSIONS:
                arg_name = args[arg_i]
                arg_i += 1
                if arg_name not in values:
                    return None  # a real function parameter we don't have a concrete value for -- refuse
                out.append(values[arg_name])
                i += 2
            else:
                out.append(fmt[i])
                i += 1
        return "".join(out)
