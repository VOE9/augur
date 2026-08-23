"""Offline tests for FormatStringPrefixDeriver -- no network, no compiler."""
from __future__ import annotations

from augur.pattern.format_string_prefix import FormatStringPrefixDeriver
from augur.pattern.function_extractor import FunctionExtractor

REAL_RTCON_GETCRASHADDRESS = '''
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


def _extract():
    return FunctionExtractor().find_function(REAL_RTCON_GETCRASHADDRESS, "getCrashAddress")


def test_derives_real_prefix_with_index_zero():
    fn = _extract()
    result = FormatStringPrefixDeriver().derive(fn.full_text, "report", {"index": "0"})
    assert result is not None
    assert result.literal_bytes == "#0 "
    assert result.needle_variable == "index_str"


def test_derives_different_prefix_for_different_index_value():
    fn = _extract()
    result = FormatStringPrefixDeriver().derive(fn.full_text, "report", {"index": "42"})
    assert result.literal_bytes == "#42 "


def test_refuses_when_needed_param_value_is_missing():
    fn = _extract()
    assert FormatStringPrefixDeriver().derive(fn.full_text, "report", {}) is None


def test_refuses_when_no_strstr_call_present():
    source = "void f(const char *x) {\n  int y = 1;\n}\n"
    fn = FunctionExtractor().find_function(source, "f")
    assert FormatStringPrefixDeriver().derive(fn.full_text, "x", {}) is None


def test_refuses_unsupported_conversion_specifier():
    source = '''void f(const char *report, double amount) {
  char needle[32];
  snprintf(needle, 32, "$%f ", amount);
  char *pc = strstr(report, needle);
}
'''
    fn = FunctionExtractor().find_function(source, "f")
    assert FormatStringPrefixDeriver().derive(fn.full_text, "report", {"amount": "1.0"}) is None
