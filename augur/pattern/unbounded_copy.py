"""Detects the specific, mechanically verifiable bug shape this tool
targets: a copy of caller-controlled bytes into a fixed-size buffer where
the copy length is not bounded by the bytes that are actually available.

Supported copy forms, all of which mean "a fixed-size destination receives
data derived from a caller-supplied string":

  memcpy(dest, src, N)      fixed-size byte copy, N a literal
  memmove(dest, src, N)     same, overlap guarantee dropped
  strcpy(dest, src)         copies until NUL -- unbounded by construction
  strncpy(dest, src, N)     copies at most N bytes, N a literal
  sprintf(dest, fmt, src)   copies until NUL through a format call

This is NOT general taint/dataflow analysis. It is a narrow, single-pass
tracker over exactly these statement shapes, over a taint set that grows
only through pointer declarations and pointer assignments. A function that
reaches the same unsafe copy through a loop, a helper-function call, or
several reassignment steps will not be detected -- reported as "not found,"
never guessed at.

Guarded copies ARE reported, carrying `guarded=True` plus the text of the
guard. That is deliberate and load-bearing for two reasons: a guarded copy
must never be claimed as a live bug, and provenance still needs to walk
history through the guarded shape to find where it was introduced.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_PTR_DECL_RE = re.compile(r"\bchar\s*\*\s*(\w+)\s*(?:=[^;]*)?;")
# Not anchored to a line start. A `char *q;` / `q = f(param);` pair is
# routinely written on one line, and an anchored pattern silently missed
# every such spelling -- the taint chain simply stopped there. The
# lookbehind keeps matches off struct members (`a.b =`), arrow assignments
# (`a->b =`), and compound names.
_PLAIN_ASSIGN_RE = re.compile(r"(?<![.\w>])(\w+)\s*=(?!=)\s*([^;]+);")

# `char a[16], b[8];` declares two buffers, not one. A single
# `char\s+(\w+)\s*\[(\d+)\]` pattern only ever matched the first name in
# such a declaration, so any function declaring its buffers that way had
# all but the first one invisible to the detector. Declarations are found
# first, then each declarator is read out on its own.
#
# Only the DECLARATOR is read, never its initializer: `char c = buf[0];`
# indexes an existing buffer, and reading every `name[N]` in the statement
# recorded `buf` as a zero-byte array, overwriting its real size. Flat
# `{...}` and `(...)` groups are allowed so that `char buf[16] = {0};` and
# `char buf[8], *p = strchr(s, ':');` are still seen as declarations.
_ARRAY_DECL_RE = re.compile(r"\bchar\s+((?:[^;(){}]|\([^();{}]*\)|\{[^{};]*\})+);")
_ARRAY_DECLARATOR_RE = re.compile(r"\s*(\w+)\s*\[\s*(\d+)\s*\]\s*")
_PTR_ASSIGN_RE = re.compile(r"\bchar\s*\*\s*(\w+)\s*=\s*([^;]+);")

_MEMCPY_RE = re.compile(r"\bmemcpy\s*\(\s*(\w+)\s*,\s*([^,]+?)\s*,\s*(\d+)\s*\)")
_MEMMOVE_RE = re.compile(r"\bmemmove\s*\(\s*(\w+)\s*,\s*([^,]+?)\s*,\s*(\d+)\s*\)")
_STRCPY_RE = re.compile(r"\bstrcpy\s*\(\s*(\w+)\s*,\s*([^;]+?)\s*\)")
_STRNCPY_RE = re.compile(r"\bstrncpy\s*\(\s*(\w+)\s*,\s*([^,]+?)\s*,\s*(\d+)\s*\)")
_SPRINTF_RE = re.compile(r"\bsprintf\s*\(\s*(\w+)\s*,\s*[^,]+,\s*([^;]+?)\s*\)")

# --- Confirmed guards -------------------------------------------------------
#
# A guard is only reported as protecting a copy when every one of these can be
# established from the text. Anything short of that is reported as UNGUARDED,
# because reporting an unguarded copy as guarded is a confident false claim,
# while the reverse only produces work for a human to check.
#
# Established by counterexample, each with an AddressSanitizer run showing the
# copy really does overflow (see scripts/verify_guard_hussein.py):
#
#   direction    `if (strlen(src) > 8) return;` returns when the input is too
#                LONG. Only a `<`/`<=` comparison excludes inputs too SHORT.
#   sufficiency  `if (strlen(src) < 2) return; memcpy(buf, src, 8);` still
#                over-reads at every length from 2 to 7. The bound must be at
#                least the number of bytes the copy reads.
#   dominance    `if (flag) { if (strlen(src) < 8) return; }` only returns
#                when another variable is also true. The guard must sit at
#                the same brace depth as the copy, not inside a branch or loop.
#   jump target  `goto`/`break`/`continue` say nothing about where control
#                goes. `if (len < 8) goto copy;` jumps TO the copy. Without a
#                control-flow graph these cannot be shown to prevent the copy,
#                so they are not counted.
#   pointer move `if (strlen(src) < 8) return; p += 7; memcpy(buf, p, 8);`
#                measures a different string from the one that gets copied.
#   comments     `/* if (strlen(src) < 8) return; */` is a comment. Comments
#                and string literals are stripped before anything is matched.
#   read vs write `if (strlen(src) < 8) return; strcpy(buf, src);` bounds how
#                many bytes may be READ; strcpy writes strlen(src)+1, so the
#                guard does not constrain the write at all.
#
# A confirmed guard therefore means: same source pointer, unmoved; an
# `<`/`<=` bound on that pointer's remaining length, numerically sufficient
# for this specific copy; an unconditional early return; at the copy's own
# brace depth.
#
# The early return may carry a value (`return NULL;`, `return -1;`) or be a
# call to `exit(...)`. Accepting only a bare `return;` meant every guard in a
# non-void function went unrecognised, and `exit` was listed but could never
# match, since `exit` is always followed by its argument list.
_GUARD_RE = re.compile(
    r"(?P<indent>[ \t]*)if\s*\(\s*strlen\s*\(\s*(?P<var>\w+)\s*\)"
    r"\s*(?P<op><=?)\s*(?P<bound>\d+)\s*\)\s*(?P<brace>\{)?\s*"
    r"(?:return\b[^;{}]*|exit\s*\([^;{}]*\))"
    r"\s*;",
    re.MULTILINE,
)

# Copies whose write size is not bounded by the copy's own length argument,
# and which therefore cannot be protected by a bound on the remaining length
# of the source.
_WRITES_WHOLE_STRING = {"strcpy", "sprintf"}

# Copies whose length is computed rather than literal cannot be evaluated
# from the source text alone -- `memcpy(buf, pc, copy_len)` says nothing
# without knowing copy_len. They are not matched, which is the conservative
# direction: the fixed version of a function is then "not found", exactly
# what provenance needs to stop its backward walk at the fix.


@dataclass(frozen=True)
class UnboundedCopyFinding:
    dest_buffer: str
    dest_size: int
    copy_length: int
    source_expr: str
    copy_call: str
    guarded: bool = False
    guard_detail: str = ""


@dataclass(frozen=True)
class _CopySite:
    position: int
    call: str
    dest: str
    src: str
    length: int | None


def _find_copy_sites(function_text: str) -> list[_CopySite]:
    sites: list[_CopySite] = []
    for regex, call in (
        (_MEMCPY_RE, "memcpy"),
        (_MEMMOVE_RE, "memmove"),
        (_STRCPY_RE, "strcpy"),
        (_STRNCPY_RE, "strncpy"),
        (_SPRINTF_RE, "sprintf"),
    ):
        for m in regex.finditer(function_text):
            raw_length = m.group(3) if m.lastindex and m.lastindex >= 3 else None
            length = int(raw_length) if raw_length else None
            sites.append(_CopySite(m.start(), call, m.group(1), m.group(2).strip(), length))
    sites.sort(key=lambda s: s.position)
    return sites


def _find_arrays(function_text: str) -> dict[str, int]:
    """Every `char name[N]` in the text, including all names of a
    comma-separated declaration such as `char a[16], b[8];`."""
    arrays: dict[str, int] = {}
    for decl in _ARRAY_DECL_RE.finditer(function_text):
        for declarator in _split_top_level(decl.group(1), ","):
            target = _split_top_level(declarator, "=")[0]
            name = _ARRAY_DECLARATOR_RE.fullmatch(target)
            if name:
                arrays[name.group(1)] = int(name.group(2))
    return arrays


def _split_top_level(text: str, separator: str) -> list[str]:
    """Splits on `separator` outside any (), [] or {} nesting."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == separator and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def _strip_comments_and_literals(function_text: str) -> str:
    """Replaces comment and string/char-literal bodies with spaces, preserving
    every byte offset.

    Offsets are the whole point: the copy's source offset comes from a regex
    over the original text, and a guard is only meaningful at the position it
    actually occupies. Rewriting in place keeps the two aligned, and blanking
    the body (rather than deleting it) means a `strlen` inside a comment can
    never be read as a guard.
    """
    out = list(function_text)
    i, n = 0, len(function_text)
    while i < n:
        ch = function_text[i]
        nxt = function_text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "*":
            j = function_text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif ch == "/" and nxt == "/":
            j = function_text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif ch in "\"'":
            quote = ch
            j = i + 1
            while j < n:
                if function_text[j] == "\\":
                    j += 2
                    continue
                if function_text[j] == quote:
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _enclosing_blocks(text: str) -> list[int]:
    """For every offset, the index of the innermost still-open `{` before it.

    `rfind("{", 0, pos)` is not this. It finds the most recent opening brace
    whether or not that brace has since been closed, so in
    `if (flag) { ... }\nmemcpy(...)` it reports the `if`'s brace as enclosing
    the copy -- and a guard in a different, already-closed block then looks
    like it is in the same block as the copy. Tracking a stack of open
    braces gives the brace that actually contains each offset."""
    enclosing: list[int] = []
    stack: list[int] = []
    for i, ch in enumerate(text):
        enclosing.append(stack[-1] if stack else -1)
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            stack.pop()
    return enclosing


def _moves_pointer(text: str, name: str) -> bool:
    """Whether `name` is reassigned or advanced anywhere in `text`. A guard that
    measures one pointer's length says nothing about a later, moved one."""
    # Whole identifier only, and not a member (`s.src`, `s->src`): `nsrc = 3`
    # does not move `src`. `==` is a comparison, not an assignment.
    ident = rf"(?<![\w.>]){re.escape(name)}\b"
    patterns = (
        rf"{ident}\s*(?:\+\+|--)",
        rf"(?:\+\+|--)\s*{ident}",
        rf"{ident}\s*(?:=(?!=)|\+=|-=)",
    )
    return any(re.search(p, text) for p in patterns)


# Constructs between the start of the guard's block and the guard that can make
# the early return conditional or skippable.
#
# Plain `if`/`while` are deliberately NOT in this list. Nesting is already
# handled by requiring the guard and the copy to share the same enclosing
# block, and an earlier, already-completed `if` cannot skip anything -- real
# functions almost always have one (`if (p == NULL) return;`) before the
# copy, so rejecting on any `if` would make the guard unrecognisable in
# practice. The braceless form, where a preceding `if (...)` has the guard as
# its body, is caught separately by `_GUARD_IS_A_BRACELESS_BODY`.
_SKIP_BETWEEN = re.compile(r"\b(?:goto|case|default)\b")
_LABEL_BETWEEN = re.compile(r"^[ \t]*[A-Za-z_]\w*[ \t]*:", re.MULTILINE)
# `if (flag) if (len < 8) return;` -- the guard is the body of a braceless
# conditional, so the early return may simply not happen.
def _is_braceless_body(prefix: str) -> bool:
    """Whether the next statement is a conditional/loop body without braces.

    Balance the trailing header, including for-loop semicolons and nested
    calls, rather than assuming that a closing parenthesis ends an if.
    """
    prefix = prefix.rstrip()
    if re.search(r"\b(?:else|do)\s*$", prefix):
        return True
    if not prefix.endswith(")"):
        return False
    depth = 0
    for index in range(len(prefix) - 1, -1, -1):
        if prefix[index] == ")":
            depth += 1
        elif prefix[index] == "(":
            depth -= 1
            if depth == 0:
                return bool(re.search(r"\b(?:if|while|for|switch)\s*$", prefix[:index]))
    return False


def _find_guard(function_text: str, site: _CopySite, tainted: set[str], dest_size: int) -> str:
    """The text of a guard that PROVABLY prevents this copy, or "" when none
    can be established. See the block above for every condition and the
    counterexample that forced it.

    `function_text` is expected to be the already-blanked text from
    `_strip_comments_and_literals`, so offsets here and in `site` refer to
    the same string."""
    if site.src not in tainted:
        return ""
    # A copy with no fixed length argument reads or writes an amount the source
    # text does not state, so no length bound on the source can be shown to be
    # sufficient for it.
    if site.length is None or site.call in _WRITES_WHOLE_STRING:
        return ""
    # A bound on how much may be READ constrains nothing about whether the
    # destination is big enough. `if (strlen(src) < 16) return;` followed by
    # `memcpy(buf, src, 16)` into `char buf[8]` reads safely and still smashes
    # the stack; only the copy's own size relative to its destination says
    # anything about the write.
    if site.length > dest_size:
        return ""

    enclosing = _enclosing_blocks(function_text)
    copy_block = enclosing[site.position]

    for m in _GUARD_RE.finditer(function_text):
        if m.start() >= site.position:
            continue
        # Same source pointer, and that pointer not moved since the guard.
        if m.group("var") != site.src:
            continue
        if _moves_pointer(function_text[m.end():site.position], site.src):
            continue
        # Same block. Equal brace DEPTH is not enough -- two sibling blocks
        # share a depth, and a guard in one does nothing for a copy in the
        # other (`if (flag) { ... } else { memcpy(...); }`).
        if enclosing[m.start()] != copy_block:
            continue
        # Nothing between the start of that block and the guard that could
        # jump past it or place it on one side of a switch case.
        span = function_text[copy_block:site.position] if copy_block >= 0 else function_text[:site.position]
        if _SKIP_BETWEEN.search(span) or _LABEL_BETWEEN.search(span):
            continue
        # Nor may the guard itself be the braceless body of a conditional.
        if _is_braceless_body(function_text[copy_block:m.start()] if copy_block >= 0 else ""):
            continue
        # A `<`/`<=` comparison excludes inputs that are too SHORT, which is
        # the direction that matters; `>` returns when the input is too long.
        # Surviving `strlen(p) <= N` means at least N + 1 bytes remain, the
        # same guarantee as `strlen(p) < N + 1`.
        guaranteed = int(m.group("bound")) + (1 if m.group("op") == "<=" else 0)
        # Numerically sufficient: at least as many bytes must remain as the
        # copy reads.
        if guaranteed < site.length:
            continue
        return " ".join(m.group(0).split())
    return ""


class UnboundedCopyDetector:
    def find_all(self, function_text: str, tainted_params: set[str]) -> list[UnboundedCopyFinding]:
        """Every supported copy whose source traces back to a tainted
        parameter, in source order. A function with two unguarded copies
        yields two findings; returning only the first would leave the
        second unexamined.

        Comments and string literals are blanked out once, up front, and
        the blanked text is what everything is read from. Doing this only
        for guard detection left a `memcpy` inside a comment reported as a
        real copy site -- and because `find()` returns the first unguarded
        finding, the harness would then have been pointed at a commented-out
        line. `_strip_comments_and_literals` preserves byte offsets, so
        positions stay valid against the original text too.
        """
        cleaned = _strip_comments_and_literals(function_text)
        arrays = _find_arrays(cleaned)
        declared_pointers = {m.group(1) for m in _PTR_DECL_RE.finditer(cleaned)}
        tainted = set(tainted_params)

        # Forward pass. A pointer declared with an initializer is always a
        # pointer; a plain `name = expr;` is only followed when `name` is
        # already known to be a pointer, so `int n = tainted_thing;` cannot
        # be mistaken for one.
        events: list[tuple[int, str, str, bool]] = [
            (m.start(), m.group(1), m.group(2), True) for m in _PTR_ASSIGN_RE.finditer(cleaned)
        ]
        events += [
            (m.start(), m.group(1), m.group(2), False) for m in _PLAIN_ASSIGN_RE.finditer(cleaned)
        ]
        events.sort(key=lambda e: e[0])

        findings: list[UnboundedCopyFinding] = []
        seen: set[tuple[str, str, str, int | None, int]] = set()
        enclosing = _enclosing_blocks(cleaned)
        function_block = cleaned.find("{")
        event_index = 0
        for site in _find_copy_sites(cleaned):
            # Apply only assignments that precede THIS copy. A later pointer
            # assignment cannot change the origin of bytes already copied.
            while event_index < len(events) and events[event_index][0] < site.position:
                position, name, expr, is_declaration = events[event_index]
                event_index += 1
                if not is_declaration and name not in declared_pointers and name not in tainted:
                    continue
                identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", expr))
                if identifiers & tainted:
                    tainted.add(name)
                elif enclosing[position] == function_block and not _is_braceless_body(cleaned[:position]):
                    # Only an unconditional assignment can establish that a
                    # previously tainted value is no longer caller-controlled.
                    tainted.discard(name)
            if site.dest not in arrays or site.src not in tainted:
                continue
            # Two copies into the same buffer from the same source are two
            # distinct sites when the length differs, and the position
            # keeps even identical calls apart. Keying on
            # (call, dest, src) alone silently discarded the second one,
            # so a second, differently-sized unsafe copy went unexamined.
            key = (site.call, site.dest, site.src, site.length, site.position)
            if key in seen:
                continue
            seen.add(key)
            guard = _find_guard(cleaned, site, tainted, arrays[site.dest])
            findings.append(UnboundedCopyFinding(
                dest_buffer=site.dest,
                dest_size=arrays[site.dest],
                # strcpy/sprintf copy until NUL, so there is no finite
                # literal bound; recording dest_size + 1 keeps the field
                # meaningful and stable for provenance's signature match.
                copy_length=site.length if site.length is not None else arrays[site.dest] + 1,
                source_expr=site.src,
                copy_call=site.call,
                guarded=bool(guard),
                guard_detail=guard,
            ))
        return findings

    def find(self, function_text: str, tainted_params: set[str]) -> UnboundedCopyFinding | None:
        """The first unguarded finding, or the first finding if every copy
        on this path is guarded."""
        findings = self.find_all(function_text, tainted_params)
        for f in findings:
            if not f.guarded:
                return f
        return findings[0] if findings else None
