"""Detects one specific, mechanically verifiable bug shape: a fixed-size
`memcpy` into a local buffer, where the source pointer traces back to a
string-like parameter through simple, single-step pointer arithmetic
(`char *p = f(param, ...); p += ...;`), with no length check on `param`
in between.

This is NOT general taint/dataflow analysis -- it is a narrow, single-pass
tracker over exactly the two statement shapes above, chosen because they
are what the real bug this module was built to catch (RTCON's
getCrashAddress) actually looks like. A function that computes the same
unsafe copy through a different shape (a loop, a helper function call,
multiple reassignment steps) will not be detected -- reported as "not
found," never guessed at."""
from __future__ import annotations

import re
from dataclasses import dataclass

_ARRAY_DECL_RE = re.compile(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]")
_PTR_ASSIGN_RE = re.compile(r"\bchar\s*\*\s*(\w+)\s*=\s*([^;]+);")
_PTR_REASSIGN_RE = re.compile(r"\b(\w+)\s*\+=\s*([^;]+);")
_MEMCPY_RE = re.compile(r"\bmemcpy\s*\(\s*(\w+)\s*,\s*([^,]+?)\s*,\s*(\d+)\s*\)")


@dataclass(frozen=True)
class UnboundedCopyFinding:
    dest_buffer: str
    dest_size: int
    copy_length: int
    source_expr: str


class UnboundedCopyDetector:
    def find(self, function_text: str, tainted_params: set[str]) -> UnboundedCopyFinding | None:
        arrays = {m.group(1): int(m.group(2)) for m in _ARRAY_DECL_RE.finditer(function_text)}
        tainted_vars = set(tainted_params)

        events = [(m.start(), "assign", m.group(1), m.group(2)) for m in _PTR_ASSIGN_RE.finditer(function_text)]
        events += [(m.start(), "reassign", m.group(1), m.group(2)) for m in _PTR_REASSIGN_RE.finditer(function_text)]
        events.sort(key=lambda e: e[0])

        for _, kind, name, expr in events:
            references_tainted = any(v in expr for v in tainted_vars)
            if kind == "assign" and references_tainted:
                tainted_vars.add(name)
            # "reassign" (p += ...) on an already-tainted pointer keeps it
            # tainted; on an untainted one it stays untainted -- no action
            # needed either way, taint only ever grows in this tracker.

        for m in _MEMCPY_RE.finditer(function_text):
            dest, src_expr, copy_len = m.group(1), m.group(2).strip(), int(m.group(3))
            if dest in arrays and arrays[dest] >= copy_len and src_expr in tainted_vars:
                return UnboundedCopyFinding(dest_buffer=dest, dest_size=arrays[dest], copy_length=copy_len, source_expr=src_expr)
        return None
