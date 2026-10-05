"""Detector unit tests for the copy shapes and guard handling.

The runtime behaviour each of these relies on is asserted separately, under
a real AddressSanitizer, in `test_verdict_correctness.py` and
`test_sanitizer_output_parsing.py`. This file covers what the detector
decides from source text alone -- which is the part that has to be right
for the harness to ever be pointed at the right copy in the first place.
"""
from __future__ import annotations

from augur.pattern.unbounded_copy import UnboundedCopyDetector

T = {"p"}


def find_all(src: str):
    return UnboundedCopyDetector().find_all(src, T)


def test_strcpy_is_detected():
    findings = find_all(
        "static void f(const char *p) { char b[16];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " strcpy(b, q); puts(b); }"
    )
    assert len(findings) == 1
    assert findings[0].copy_call == "strcpy"
    assert findings[0].dest_buffer == "b"
    assert findings[0].dest_size == 16
    assert not findings[0].guarded


def test_sprintf_is_detected():
    findings = find_all(
        "static void f(const char *p) { char b[16];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " sprintf(b, \"%s\", q); puts(b); }"
    )
    assert [x.copy_call for x in findings] == ["sprintf"]


def test_memmove_is_reported_as_memmove_not_memcpy():
    findings = find_all(
        "static void f(const char *p) { char b[16];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " memmove(b, q, 8); puts(b); }"
    )
    assert [x.copy_call for x in findings] == ["memmove"]


def test_comma_separated_buffer_declaration_yields_every_buffer():
    """`char a[16], b[8];` declares two buffers. Only the first was
    visible to the detector before, so a second unsafe copy into `b` went
    entirely unexamined."""
    findings = find_all(
        "static void f(const char *p) { char a[16], b[8];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " memcpy(a, q, 16); memcpy(b, q, 8); puts(a); puts(b); }"
    )
    assert [(x.dest_buffer, x.copy_length) for x in findings] == [("a", 16), ("b", 8)]


def test_find_all_returns_every_copy_and_find_prefers_unguarded():
    """A guard placed BETWEEN two copies protects only what follows it.
    The first copy is reachable with no bound at all."""
    src = (
        "static void f(const char *p) { char a[16], b[8];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " memcpy(a, q, 16);"
        " if (strlen(q) < 8) return;"
        " memcpy(b, q, 8); puts(a); puts(b); }"
    )
    findings = find_all(src)
    assert len(findings) == 2
    assert {x.dest_buffer: x.guarded for x in findings} == {"a": False, "b": True}
    assert UnboundedCopyDetector().find(src, T).dest_buffer == "a"


def test_decl_then_assign_taint_is_tracked():
    """`char *q; q = f(p);` -- declaration on one line, assignment later.
    Previously unsupported, and a very ordinary spelling."""
    findings = find_all(
        "static void f(const char *p) { char b[16]; char *q;"
        " q = strstr(p, \"x\"); if (!q) return;"
        " memcpy(b, q, 16); puts(b); }"
    )
    assert len(findings) == 1
    assert findings[0].source_expr == "q"


def test_scalar_assignment_from_tainted_value_is_not_taint_propagation():
    """An int cannot carry a string pointer. Only assignments to names
    already known to be pointers are followed, so `int n = <tainted>;`
    must not taint `n` and must not make an unrelated copy look tainted."""
    findings = find_all(
        "static void f(const char *p) { char b[16];"
        " int n = 3; char *q = strstr(p, \"x\"); if (!q) return;"
        " memcpy(b, n, 16); puts(b); (void)n; }"
    )
    assert findings == []


def test_length_guard_is_recognised():
    findings = find_all(
        "static void f(const char *p) { char b[16];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " if (strlen(q) < 16) return;"
        " memcpy(b, q, 16); puts(b); }"
    )
    assert len(findings) == 1
    assert findings[0].guarded
    assert "strlen(q) < 16" in findings[0].guard_detail


def test_guard_written_after_the_copy_does_not_count():
    findings = find_all(
        "static void f(const char *p) { char b[16];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " memcpy(b, q, 16);"
        " if (strlen(q) < 16) return;"
        " puts(b); }"
    )
    assert len(findings) == 1
    assert not findings[0].guarded


def test_computed_copy_length_is_not_matched():
    """`memcpy(b, q, n)` cannot be judged from the text alone. Staying
    silent is the safe direction: it is what makes a fixed function read
    as 'not found', which is what stops provenance's backward walk."""
    assert find_all(
        "static void f(const char *p) { char b[16];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " size_t n = strlen(q); if (n > 15) n = 15;"
        " memcpy(b, q, n); puts(b); }"
    ) == []


def test_snprintf_on_the_same_buffer_is_not_treated_as_a_guard():
    """A bounded write earlier in the function does NOT make a later
    fixed-size copy safe: memcpy(b, q, 16) still overflows when q is short.
    Claiming otherwise would manufacture a false 'guarded' verdict."""
    findings = find_all(
        "static void f(const char *p) { char b[16];"
        " char *q = strstr(p, \"x\"); if (!q) return;"
        " snprintf(b, sizeof(b), \"%s\", q);"
        " memcpy(b, q, 16); puts(b); }"
    )
    assert len(findings) == 1
    assert not findings[0].guarded


def test_unrelated_copy_is_not_reported():
    assert find_all(
        "static void f(const char *p) { char b[16];"
        " memcpy(b, \"literal\", 8); puts(b); }"
    ) == []

# --- Counterexamples supplied by Hussein in review 003 -------------------
#
# Each of these was reported by him as a case where the detector claimed
# `guarded=True` while AddressSanitizer reported a real buffer overflow.
# The bodies are taken verbatim from `scripts/verify_guard_hussein.py` so the
# two cannot drift apart; running that script under a real gcc remains the
# end-to-end check that the overflow is real, and these tests are the fast
# in-process assertions that the detector agrees with it.
#
# Each name states the specific reason a bare `strlen(src) < N` comparison is
# not proof that this copy is protected.

GUARD_CASES = {
    # The comparison does not exit; the copy runs either way.
    "logging_only": (
        'if (strlen(src) < 8) puts("short");\nmemcpy(buf, src, 8);', False),
    # `>` returns when the input is too LONG. Only `<`/`<=` excludes inputs
    # that are too short, which is the direction that matters.
    "wrong_direction": (
        "if (strlen(src) > 8) return;\nmemcpy(buf, src, 8);", False),
    # Returns only below 2, but the copy reads 8 bytes: lengths 2..7 still
    # over-read, so the bound has to be at least the copy length.
    "insufficient_bound": (
        "if (strlen(src) < 2) return;\nmemcpy(buf, src, 8);", False),
    # The guard only fires when another variable is also true, so it is at a
    # deeper brace depth than the copy.
    "nested_branch": (
        "if (flag) { if (strlen(src) < 8) return; }\nmemcpy(buf, src, 8);", False),
    # `goto` jumps TO the copy. Without a control-flow graph this cannot be
    # shown to prevent it, so it is not counted as a guard at all.
    "goto_before_copy": (
        "if (strlen(src) < 8) goto copy;\ncopy: memcpy(buf, src, 8);", False),
    # A `break` in a loop says nothing about where control goes next.
    "break_before_copy": (
        "while (1) { if (strlen(src) < 8) break; break; }\nmemcpy(buf, src, 8);", False),
    # The guard measures `src`; the copy reads `p`, seven bytes further on.
    "moved_pointer": (
        "if (strlen(src) < 8) return;\nchar *p = (char *)src; p += 7;\n"
        "memcpy(buf, p, 8);", False),
    # A commented-out guard protects nothing. Comments and string literals are
    # blanked out before any matching happens.
    "guard_in_comment": (
        "/* if (strlen(src) < 8) return; */\nmemcpy(buf, src, 8);", False),
    # A bound on how many bytes may be READ does not constrain what strcpy
    # WRITES: strcpy emits strlen(src)+1 bytes, so this guard is not a write
    # protection at all.
    "strcpy_lower_bound": (
        "if (strlen(src) < 8) return;\nstrcpy(buf, src);", False),
    # The control: same pointer, `<`, bound equal to the copy length, an
    # unconditional early return at the copy's own depth. This one IS guarded.
    "safe_control": (
        "if (strlen(src) < 8) return;\nmemcpy(buf, src, 8);", True),
}


def _guarded(body: str):
    source = "void f(const char *src, int flag) {\nchar buf[8];\n" + body + "\n}\n"
    findings = UnboundedCopyDetector().find_all(source, {"src"})
    return findings[0].guarded if findings else None


def test_every_hussein_guard_counterexample_now_matches():
    """Regression net for HUS-004. Before the fix, eight of these ten were
    reported as guarded while ASan showed an overflow."""
    wrong = {name: _guarded(body) for name, (body, _) in GUARD_CASES.items()}
    for name, got in wrong.items():
        expected = GUARD_CASES[name][1]
        assert got == expected, f"{name}: detector said guarded={got}, expected {expected}"


def test_the_single_confirmed_guard_shape_is_still_recognised():
    """The strictness must not become useless: the one shape that really is
    provable still has to be found, or every copy would be reported as
    unguarded and the tool would cry wolf on fixed code."""
    body = "if (strlen(src) < 8) return;\nmemcpy(buf, src, 8);"
    assert _guarded(body) is True


def test_guard_on_a_braced_early_return_at_the_same_depth_is_accepted():
    body = "if (strlen(src) < 8) { return; }\nmemcpy(buf, src, 8);"
    assert _guarded(body) is True


def test_guard_after_the_copy_does_not_protect_it():
    assert _guarded("memcpy(buf, src, 8);\nif (strlen(src) < 8) return;") is False


def test_a_bound_larger_than_the_copy_length_still_protects_it():
    """Being stricter than necessary about the bound is fine: >= the copy
    length means at least that many bytes remain, which is what the copy
    needs."""
    assert _guarded("if (strlen(src) < 99) return;\nmemcpy(buf, src, 8);") is True


def test_strcpy_is_never_confirmed_guarded_by_a_length_bound_alone():
    """No finite bound on the remaining length makes an unbounded strcpy
    safe, so it must never be described as protected."""
    for bound in (0, 1, 7, 8, 64, 4096):
        assert _guarded(f"if (strlen(src) < {bound}) return;\nstrcpy(buf, src);") is False


def test_guard_measurement_of_a_different_variable_is_not_a_guard():
    assert _guarded("if (strlen(other) < 8) return;\nmemcpy(buf, src, 8);") is False


def test_compound_condition_is_not_accepted_as_a_plain_guard():
    """`&&`/`||` mean the early return may not fire, so the simple shape does
    not apply and the copy is not provably protected."""
    assert _guarded("if (flag && strlen(src) < 8) return;\nmemcpy(buf, src, 8);") is False


def test_string_literal_containing_a_guard_is_ignored():
    assert _guarded('const char *m = "if (strlen(src) < 8) return;";\nmemcpy(buf, src, 8);') is False


def test_comment_offsets_are_preserved_so_sites_are_still_found():
    """Stripping comments must not shift the copy's position out from under
    the offsets the copy regex already reported."""
    body = "/* a comment mentioning memcpy(buf, src, 8); */\nmemcpy(buf, src, 8);"
    findings = UnboundedCopyDetector().find_all(
        "void f(const char *src) {\nchar buf[8];\n" + body + "\n}\n", {"src"}
    )
    # Two textual sites exist -- one inside the comment. The one inside the
    # comment must not be reported, and the real one must still be found at
    # the right offsets.
    assert len(findings) == 1
    assert findings[0].copy_length == 8
    assert findings[0].copy_call == "memcpy"


def test_indexing_a_buffer_in_an_initializer_does_not_redeclare_it():
    """`char c = buf[0];` reads an element. Treating it as a declaration
    recorded `buf` as a zero-byte array and overwrote its real size."""
    findings = UnboundedCopyDetector().find_all(
        "void f(const char *src) {\nchar buf[16];\nchar first = buf[0];\n"
        "memcpy(buf, src, 16);\n}\n", {"src"}
    )
    assert len(findings) == 1
    assert findings[0].dest_size == 16


def test_buffers_with_brace_or_call_initializers_are_still_declared():
    for decl in ("char buf[8] = {0};", "char buf[8], *q = strchr(src, ':');"):
        findings = UnboundedCopyDetector().find_all(
            "void f(const char *src) {\n" + decl + "\nmemcpy(buf, src, 8);\n}\n", {"src"}
        )
        assert [f.dest_size for f in findings] == [8], decl


def test_early_return_with_a_value_or_exit_is_a_guard():
    """Non-void functions return a value, and `exit` always takes an
    argument; a guard written either way protects the copy just the same."""
    for exit_stmt in ("return 0;", "return NULL;", "return -1;", "{ return 0; }", "exit(1);"):
        assert _guarded(f"if (strlen(src) < 8) {exit_stmt}\nmemcpy(buf, src, 8);") is True, exit_stmt


def test_less_or_equal_bound_is_one_byte_stronger():
    """Surviving `strlen(src) <= N` guarantees N + 1 bytes."""
    assert _guarded("if (strlen(src) <= 7) return;\nmemcpy(buf, src, 8);") is True
    assert _guarded("if (strlen(src) <= 6) return;\nmemcpy(buf, src, 8);") is False


def test_comparing_or_naming_a_lookalike_does_not_move_the_pointer():
    """`src == x` compares and `nsrc = 3` assigns another variable; neither
    moves `src`, so neither invalidates the guard."""
    for between in ("if (src == NULL) return;", "int nsrc; nsrc = 3;", "flag = src != 0;"):
        body = f"if (strlen(src) < 8) return;\n{between}\nmemcpy(buf, src, 8);"
        assert _guarded(body) is True, between
    assert _guarded("if (strlen(src) < 8) return;\nsrc = \"\";\nmemcpy(buf, src, 8);") is not True
