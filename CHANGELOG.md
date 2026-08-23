# Changelog

## 0.3.0

**New:** a third section, `provenance`. Given a fix commit for the same
narrow bug shape `harness` targets, finds the commit that actually
introduced the vulnerable pattern -- structurally (re-running the same
detector against every historical revision of the function), not "the
last commit that touched this line" the way classic SZZ does, which is
well documented to be fooled by pure reformatting/renaming commits --
and maps that introduction point to the tagged versions that actually
contain it.

- Added `augur/provenance/` (`VulnerabilityIntroductionFinder`,
  `VersionRangeMapper`, `ProvenancePipeline`) and the `augur provenance`
  CLI command.
- Extended `GitRepository` with `parent_of`, `file_history_before`,
  `is_ancestor`, and `tags_sorted_by_date`.
- Verified against a controlled real git repository (six commits
  including a deliberate cosmetic rename of the tainted variable, four
  tags) confirming the tool finds the true introduction commit and the
  correct vulnerable-tag range.
- Verified against a real, external repository, not a synthetic one:
  `kaist-hacking/RTCON`, using this project's own real, previously
  merged fix commit (`e8b4127`, PR #2). The tool's answer (vulnerable
  since the repository's first commit) was checked independently by
  hand against `git log --follow` and `git show` on the real repo, and
  the two agree.
- One real bug found by the controlled test: the first version of the
  signature comparison included the tainted variable's literal *name*,
  so the deliberate cosmetic-rename commit in the test broke the walk
  early. Fixed by comparing only the renaming-independent parts of the
  shape (`dest_size`/`copy_length`). See METHODOLOGY.md.
- 23/23 tests passing (up from 19).

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
