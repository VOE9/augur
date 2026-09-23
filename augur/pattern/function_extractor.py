"""Extracts one named C/C++ function's full source text.

When Clang is available, the extractor uses Clang's AST to identify the
definition boundaries and then applies the existing conservative signature
classifier. The brace-matching implementation remains an explicit fallback
for minimal environments and for source that Clang cannot parse.
"""
from __future__ import annotations

import re

from .signature import FunctionSignature

_SIGNATURE_RE = re.compile(
    r"^[ \t]*((?:static\s+|inline\s+)*[\w \t]+?[\w \t\*]*?)\s+(\w+)\s*\(([^;{}]*)\)\s*\{",
    re.MULTILINE,
)
_ATTRIBUTE_RE = re.compile(r"__attribute__\s*\(\(")


class ExtractedFunction:
    def __init__(self, name: str, full_text: str, signature: FunctionSignature | None):
        self.name = name
        self.full_text = full_text
        self.signature = signature


class FunctionExtractor:
    def __init__(self, prefer_clang: bool = True):
        self.prefer_clang = prefer_clang

    def find_function(self, source: str, function_name: str) -> ExtractedFunction | None:
        if self.prefer_clang:
            from .clang_function_extractor import ClangFunctionExtractor

            parsed = ClangFunctionExtractor().find_function(source, function_name)
            if parsed is not None and parsed.signature is not None:
                return parsed

        return self._find_with_brace_matching(source, function_name)

    def _find_with_brace_matching(self, source: str, function_name: str) -> ExtractedFunction | None:
        cleaned = self._strip_attributes(source)
        for m in _SIGNATURE_RE.finditer(cleaned):
            if m.group(2) != function_name:
                continue
            brace_start = m.end() - 1
            end = self._matching_brace(cleaned, brace_start)
            if end is None:
                continue
            body = cleaned[m.start():end + 1]
            signature = FunctionSignature.parse(m.group(1), m.group(2), m.group(3))
            return ExtractedFunction(name=function_name, full_text=body, signature=signature)
        return None

    @staticmethod
    def _strip_attributes(source: str) -> str:
        """Removes __attribute__((...)) blocks with real paren matching
        (their arguments, e.g. no_sanitize("address"), contain their own
        parens, so a non-greedy regex alone would stop too early)."""
        out = []
        i = 0
        for m in _ATTRIBUTE_RE.finditer(source):
            out.append(source[i:m.start()])
            depth = 2  # the regex itself already consumed both opening '(('
            j = m.end() - 1
            for j in range(m.end(), len(source)):
                if source[j] == "(":
                    depth += 1
                elif source[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
            i = j + 1
        out.append(source[i:])
        return "".join(out)

    @staticmethod
    def _matching_brace(text: str, open_index: int) -> int | None:
        depth = 0
        for i in range(open_index, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return i
        return None
