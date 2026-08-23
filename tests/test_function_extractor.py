"""Offline tests for FunctionExtractor/FunctionSignature -- no network,
no compiler needed. Two of these lock in real bugs found while building
this module, not speculative edge cases."""
from __future__ import annotations

from augur.pattern.function_extractor import FunctionExtractor
from augur.pattern.signature import FunctionSignature, Parameter

REAL_RTCON_GETCRASHADDRESS = '''
#include <string.h>

__attribute__((no_sanitize("coverage"), no_sanitize("address"))) static void *
getCrashAddress(const char *report, int index) {
  char addr[20];
  char index_str[6];

  memset(index_str, 0, 6);
  snprintf(index_str, 6, "#%d ", index);
  char *pc = strstr(report, index_str);
  if (pc == NULL) return NULL;
  pc += strlen(index_str);

  memset(addr, 0, 20);
  memcpy(addr, pc, 20);

  char *end = strchr(addr, ' ');
  if (end != NULL) { end[0] = '\\0'; } else { return NULL; }

  return (void *)strtoul(addr, NULL, 16);
}
'''


def test_extracts_real_function_with_multiline_gcc_attribute():
    """Regression test: the attribute-stripping paren counter was
    off-by-one (started counting from the second '(' instead of
    accounting for both already-consumed opening parens), which left a
    stray ')' in the cleaned source and made the signature regex fail
    to match at all. Caught by testing against this exact real function."""
    fn = FunctionExtractor().find_function(REAL_RTCON_GETCRASHADDRESS, "getCrashAddress")
    assert fn is not None
    assert "memcpy(addr, pc, 20)" in fn.full_text
    assert fn.full_text.count("{") == fn.full_text.count("}")


def test_real_function_signature_parses_as_simple():
    fn = FunctionExtractor().find_function(REAL_RTCON_GETCRASHADDRESS, "getCrashAddress")
    assert fn.signature is not None
    assert fn.signature.is_simple()
    assert [p.raw for p in fn.signature.parameters] == ["const char *report", "int index"]


def test_returns_none_for_missing_function():
    assert FunctionExtractor().find_function(REAL_RTCON_GETCRASHADDRESS, "doesNotExist") is None


def test_pointer_to_non_char_is_not_primitive():
    """Regression test: is_primitive() originally ignored pointer_depth
    entirely, so `int *count` was misclassified as a synthesizable
    primitive parameter -- Augur has no logic to synthesize a meaningful
    value for "pointer to a single int" (out-param? array? optional?),
    so this must count as NOT simple, not silently assumed safe."""
    param = Parameter("int *count")
    assert not param.is_primitive()
    sig = FunctionSignature("void", "f", [param])
    assert not sig.is_simple()


def test_char_pointer_is_simple_via_string_like_not_primitive():
    param = Parameter("const char *report")
    assert not param.is_primitive()
    assert param.is_string_like()
    sig = FunctionSignature("void", "f", [param])
    assert sig.is_simple()


def test_function_pointer_parameter_is_out_of_scope():
    assert FunctionSignature.parse("void", "f", "void (*cb)(int)") is None
