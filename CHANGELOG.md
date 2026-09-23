# Changelog

## Unreleased

**New:** an opt-in `memory-safety` Radar variant for C/C++ commits. It uses
an explicit added-line vocabulary for memory/size operations together with
guards or comparisons, while leaving the default Radar behavior unchanged.

**Experiment interface:** Radar now supports JSON evidence output plus
per-signal weight and confidence-threshold overrides. The selected
configuration is embedded in the JSON result for reproducibility.

**Performance:** classic B-SZZ now blames changed line ranges in one Git
invocation per range, and provenance tag checks use `git tag --contains`
instead of one ancestry check per tag.

## 0.4.0

**New:** `augur/provenance/szz_baseline.py` -- an implementation of
classic B-SZZ (Sliwerski, Zimmermann & Zeller, 2005), written directly
rather than vendored, so the comparison rests on an auditable algorithm
instead of an opaque dependency.

This project's docs have repeatedly claimed that classic SZZ is fooled by
a purely cosmetic rename while the structural `provenance` finder is not.
That claim now has an executable check behind it
(`tests/test_szz_baseline.py`): against a real git repository whose
history contains a known introduction commit and a later rename-only
commit, B-SZZ reports the rename commit and `provenance` reports the true
introduction.

- `ClassicSZZ.find_introducing_commit()` -- blames every line the fix
  removed or changed at the fix's parent revision and reports the most
  recently authored of those commits, which is what B-SZZ does. A fix
  that only adds lines has no answer under this algorithm; that is
  reported honestly rather than guessed at.
- `GitRepository` gained `removed_line_ranges()` (parses `git diff
  --unified=0` hunk headers, skipping pure additions) and `blame_line()`
  (`git blame --porcelain -L n,n`).
- Test fixtures moved to `tests/conftest.py` so the provenance and SZZ
  tests exercise the same repository.

25 tests pass.

## 0.3.1

Packaging only, no behavior change: added `pyproject.toml` so Augur can
be installed as a regular dependency (`pip install git+https://...`)
instead of only run from a checkout. Needed to let
[cve-explain](https://github.com/VOE9/cve-explain) depend on Augur's
`provenance` module directly for its own `--verify-git` feature.

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
