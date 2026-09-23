"""Optional Clang-AST function extraction.

Clang is used as a parser, not as a vulnerability oracle. The backend finds
the byte range of a real function definition in the translation unit and
returns the original source text for the existing narrow harness pipeline.
If Clang is missing, cannot parse the translation unit, or cannot find the
requested definition, the caller can fall back to the legacy extractor.
"""
from __future__ import annotations

import json
import shutil
import subprocess


class ClangFunctionExtractor:
    def __init__(self, clang_binary: str | None = None, timeout: int = 30):
        self.clang_binary = clang_binary or shutil.which("clang")
        self.timeout = timeout

    def find_function(self, source: str, function_name: str):
        if not self.clang_binary:
            return None

        # C first preserves C semantics for C-like input. C++ is a fallback
        # for callers that provide C++ source as an in-memory string.
        for language, standard in (("c", "c11"), ("c++", "c++17")):
            tree = self._parse(source, language, standard)
            if tree is None:
                continue
            node = self._find_definition(tree, function_name)
            if node is None:
                continue
            full_text = self._slice_range(source, node)
            if full_text:
                # Reuse the established conservative signature classifier.
                # The AST determines function boundaries; the classifier
                # still decides whether a harness is safe to make.
                from .function_extractor import ExtractedFunction, FunctionExtractor

                legacy = FunctionExtractor(prefer_clang=False)
                # The legacy extractor deliberately removes sanitizer
                # attributes before generating a harness. Keeping that
                # behavior is essential: carrying no_sanitize("address")
                # into the generated test would disable the very detector
                # the harness is meant to exercise.
                cleaned = legacy._strip_attributes(full_text)
                parsed = legacy.find_function(cleaned, function_name)
                signature = parsed.signature if parsed is not None else None
                return ExtractedFunction(function_name, cleaned, signature)
        return None

    def _parse(self, source: str, language: str, standard: str) -> dict | None:
        try:
            result = subprocess.run(
                [
                    self.clang_binary,
                    "-x", language,
                    f"-std={standard}",
                    "-fsyntax-only",
                    "-ferror-limit=0",
                    "-Xclang", "-ast-dump=json",
                    "-",
                ],
                input=source,
                text=True,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None

    @classmethod
    def _find_definition(cls, node: dict, function_name: str) -> dict | None:
        if (
            node.get("kind") in {"FunctionDecl", "CXXMethodDecl"}
            and node.get("name") == function_name
            and any(child.get("kind") == "CompoundStmt" for child in node.get("inner", []))
        ):
            return node
        for child in node.get("inner", []):
            if isinstance(child, dict):
                found = cls._find_definition(child, function_name)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _slice_range(source: str, node: dict) -> str:
        byte_range = node.get("range", {})
        begin = byte_range.get("begin", {}).get("offset")
        end = byte_range.get("end", {}).get("offset")
        if not isinstance(begin, int) or not isinstance(end, int) or begin < 0 or end < begin:
            return ""
        raw = source.encode("utf-8")
        try:
            return raw[begin:end + 1].decode("utf-8")
        except UnicodeDecodeError:
            return ""
