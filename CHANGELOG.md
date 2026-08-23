# Changelog

## 0.2.0

**New:** automatic seed derivation for `harness`. `--seed` is now
optional — when omitted, `augur.harness.pipeline.HarnessPipeline.analyze_auto()`
(wired to the CLI automatically) reads the target function's own
`snprintf(...)`-then-`strstr(...)` matching logic and mechanically
derives the exact literal prefix a valid input needs, using the
concrete parameter values passed via `--param`. No human-supplied
example input required for this shape.

- Added `augur/pattern/format_string_prefix.py`
  (`FormatStringPrefixDeriver`).
- Added `HarnessPipeline.analyze_auto()` and the `seed_derivation_failed`
  verdict, returned honestly when a function's matching logic doesn't
  fit the supported shape (falls back to `--seed`, never a guess).
- Verified against the same real ground truth as 0.1.0
  (`kaist-hacking/RTCON#2`'s `getCrashAddress`): `analyze_auto()`
  reproduces the identical `confirmed_regression_fix` verdict with zero
  human-supplied seed content. See `tests/test_auto_seed_integration.py`.
- `angr` was installed and evaluated as a fuller, symbolic-execution-based
  alternative that would remove `--seed` for arbitrary matching logic,
  not just this one shape. Not shipped — see METHODOLOGY.md for why.
- 19/19 tests passing (up from 12 in 0.1.0).

## 0.1.0

Initial release. Two sections:

- `radar` — scans a local git clone and flags commits that look like
  undisclosed ("silent") security fixes, reusing this portfolio's
  already-debugged `silent-patch-finder` detection logic.
- `harness` — for a narrow C/C++ bug shape (fixed-size `memcpy` from a
  string parameter reached through simple pointer arithmetic), attempts
  an automatic differential AddressSanitizer proof comparing a pre-fix
  and post-fix function body.
- Validated end to end against real ground truth: `kaist-hacking/RTCON#2`'s
  `getCrashAddress` (merged, previously hand-verified).
- Six real bugs found and fixed during development, each with a
  regression test — see METHODOLOGY.md.
- 12/12 tests passing.
