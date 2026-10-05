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

from .unbounded_copy import _strip_comments_and_literals

_SNPRINTF_RE = re.compile(
    r'\bsnprintf\s*\(\s*(?P<needle>\w+)\s*,\s*(?P<size>\d+)\s*,\s*'
    r'"(?P<format>(?:[^"\\]|\\.)*)"\s*(?:,\s*(?P<args>[^)]*))?\)'
)
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
        cleaned = _strip_comments_and_literals(function_text)
        search_call = self._find_search_call(cleaned, string_param_name)
        if search_call is None:
            return None
        haystack_var, needle_var, search_pos = search_call

        snprintf_match = None
        for m in _SNPRINTF_RE.finditer(function_text):
            if m.group("needle") == needle_var and m.start() < search_pos and cleaned[m.start():].startswith("snprintf"):
                snprintf_match = m  # keep the last one before the search call

        if snprintf_match is None:
            return None

        size = int(snprintf_match.group("size"))
        if size == 0:
            return None  # snprintf writes no terminated needle at size zero.
        intervening = cleaned[snprintf_match.end():search_pos]
        if re.search(rf"\b{re.escape(needle_var)}\b", intervening):
            return None  # A modified/aliased needle cannot be reconstructed here.
        fmt, args_text = snprintf_match.group("format"), snprintf_match.group("args") or ""
        args = [a.strip() for a in args_text.split(",") if a.strip()]
        rendered = self._render(fmt, args, other_param_values)
        if rendered is None:
            return None
        # snprintf reserves one byte for NUL, truncating BYTES, not characters.
        prefix = rendered.encode("utf-8")[:size - 1].split(b"\0", 1)[0]
        try:
            return DerivedPrefix(literal_bytes=prefix.decode("utf-8"), needle_variable=needle_var)
        except UnicodeDecodeError:
            return None  # A split UTF-8 character needs a binary seed API.

    @staticmethod
    def _find_search_call(function_text: str, string_param_name: str) -> tuple[str, str, int] | None:
        for m in _STRSTR_RE.finditer(function_text):
            haystack, needle = m.group(1), m.group(2)
            if haystack == string_param_name:
                return haystack, needle, m.start()
        return None

    @staticmethod
    def _render(fmt: str, args: list[str], values: dict[str, str]) -> str | None:
        fmt = _decode_c_string(fmt)
        if fmt is None:
            return None
        fmt = fmt.split("\0", 1)[0]
        out, arg_i = [], 0
        i = 0
        while i < len(fmt):
            if fmt[i] == "%":
                if i + 1 < len(fmt) and fmt[i + 1] == "%":
                    out.append("%")
                    i += 2
                    continue
                if i + 1 == len(fmt) or f"%{fmt[i + 1]}" not in _SUPPORTED_CONVERSIONS or arg_i >= len(args):
                    return None
                raw = values.get(args[arg_i], args[arg_i])
                arg_i += 1
                if fmt[i + 1] == "d":
                    number = _parse_c_int(raw)
                    if number is None or not -(2**31) <= number < 2**31:
                        return None
                    out.append(str(number))
                else:
                    if not re.fullmatch(r'"(?:[^"\\]|\\.)*"', raw):
                        return None
                    literal = _decode_c_string(raw[1:-1])
                    if literal is None:
                        return None
                    out.append(literal.split("\0", 1)[0])
                i += 2
            else:
                out.append(fmt[i])
                i += 1
        return "".join(out)


def _parse_c_int(raw: str) -> int | None:
    """Accept integer literals with C's decimal, octal and hex semantics."""
    raw = raw.strip()
    if not re.fullmatch(r"[+-]?(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)", raw):
        return None
    unsigned = raw.lstrip("+-")
    base = 16 if unsigned.lower().startswith("0x") else 8 if unsigned.startswith("0") else 10
    return int(raw, base)


def _decode_c_string(body: str) -> str | None:
    """Decode the supported C escapes as bytes, refusing uncertain forms."""
    raw = bytearray()
    escapes = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11,
               "\\": 92, '"': 34, "'": 39, "?": 63}
    index = 0
    while index < len(body):
        ch = body[index]
        if ch != "\\":
            raw.extend(ch.encode("utf-8"))
            index += 1
            continue
        index += 1
        if index == len(body):
            return None
        ch = body[index]
        if ch in escapes:
            raw.append(escapes[ch])
            index += 1
        elif ch in "01234567":
            match = re.match(r"[0-7]{1,3}", body[index:])
            number = int(match.group(), 8)
            if number > 255:
                return None
            raw.append(number)
            index += len(match.group())
        elif ch == "x":
            match = re.match(r"[0-9a-fA-F]+", body[index + 1:])
            if match is None or int(match.group(), 16) > 255:
                return None
            raw.append(int(match.group(), 16))
            index += 1 + len(match.group())
        else:
            return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
