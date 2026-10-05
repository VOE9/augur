# Changelog

## 0.5.0

### Pre-release correctness checks (2026-10-05)

- Reject conditional loop guards that do not dominate the tracked copy.
- Apply pointer assignments in source order, match whole identifiers, and
  clear input taint after unconditional replacement with independent data.
- Follow file renames using the path valid at each historical revision;
  accept Git worktrees.
- Validate both function signatures and preserve argument positions across
  parameter renames. Rename declaration tokens without corrupting types.
- Encode seeds as UTF-8 bytes and sweep byte lengths; refuse embedded NUL.
- Restrict Radar's source view to each diff's actual file header.
- Derive snprintf prefixes with C literal formatting and destination-size
  truncation; refuse ambiguous needle modifications and unsupported forms.
- Ignore comments and literal braces in the fallback function extractor.
- Align the CLI/package version, enforce isolated installation checks, and
  require critical ASan test execution in CI.
- Read only declarators as array declarations: `char c = buf[0];` recorded
  `buf` as a zero-byte array, overwriting its real size. Declarations with
  `{0}` or call initializers are now recognised.
- Recognise guards whose early exit is `return <value>;` or `exit(...);`
  (previously only a bare `return;` matched), and `strlen(p) <= N` as a
  bound of N + 1. An unrecognised guard made provenance treat guarded
  revisions as vulnerable.
- A pointer is no longer considered moved by `p == x` or by assignments to
  identifiers that merely end in its name.
- Stream `git log` stderr to a file so a large stderr cannot block the scan.

Six defects were found by an independent review (`novehtieonr.md`, review
001) and fixed. Three of them could each produce a *confirmed* result that
was not true, which is the one failure mode this project treats as
unacceptable.

### Fixed

**A `confirmed_regression_fix` verdict could be issued for a version that
was never shown to be safe.** The verdict was decided from the length at
which the old version *first* crashed, and the new version was only
checked at that one length. A partially-fixed version -- one that is clean
at short inputs but still overflows at longer ones -- therefore passed as
"confirmed". The decision is now made from the complete crash-length sets
of both implementations, and `confirmed_regression_fix` additionally
requires the new version to have crashed at *no* length in the sweep.
Two new verdicts replace the vague `inconclusive`: `partial_fix` and
`regression_introduced_by_fix`.

**A run that could not be evaluated counted as a run that succeeded.** A
timeout, an unexplained non-zero exit, and a harness that failed to start
all produce `crashed=False`, which the classifier read as "the new version
did not crash". `RunResult` now carries an explicit `status` of
clean/error/failed, and confirmation additionally requires that every
input in the sweep was actually evaluated. Anything unevaluated yields
`inconclusive`, naming the affected lengths and reasons.

**A memory leak was counted as a memory-safety violation.** Crash detection
matched the string `AddressSanitizer` anywhere in stderr, and a
LeakSanitizer report's summary line is `SUMMARY: AddressSanitizer: N
byte(s) leaked` -- so any target function that simply allocated without
freeing "crashed" at every input length. Output is now parsed by the
sanitizer's own error class, and a leak is reported as a leak, never as a
crash. `ASAN_OPTIONS=detect_leaks=0` is set by default, with
`detect_leaks=True` available on the runner.

**`AddressSanitizer:DEADLYSIGNAL` was classified as no error at all.** It
is an intercepted fatal signal -- a real crash -- and is now recorded as
`deadly-signal`.

**Function extraction missed ordinary one-line pointer-returning
declarations.** The signature pattern required whitespace between the
return type and the function name, so `static char *name(...)` was never
found and was reported as "could not locate function", indistinguishable
from the function being absent. The real ground-truth function only
matched because its declaration happened to span two lines.

**Merge commits carried no diff, so a silent fix integrated by merge was
invisible.** `git log -p` prints no diff at all for a merge commit. Radar
now passes `--diff-merges=first-parent` (git 2.31+), falling back to `-m`
on older git. The fallback deliberately avoids `--first-parent`, which
would deduplicate the diff but hide every side-branch commit.

### Changed

- The copy detector now understands `strcpy`, `strncpy`, `strncpy`-style
  bounded copies, `memmove` and `sprintf`, not just `memcpy` with a
  literal length; it recognises every buffer in a comma-separated
  declaration (`char a[16], b[8];`), reports every copy site instead of
  collapsing sites that share a destination and source, and follows taint
  through `char *p; p = f(param);`.
- A length comparison only counts as a guard when it can actually prevent
  the copy -- an early exit or a clamp. `if (len < 8) log(); memcpy(buf,
  src, 8);` is no longer described as guarded.
- Provenance walks only unguarded copies, so a properly guarded revision is
  no longer reported as where the vulnerability began, and guarded
  releases are no longer listed as affected. Copy identity now includes the
  copy function: `memcpy(buf, src, 8)` over-reads a short source while
  `strncpy(buf, src, 8)` does not.
- `char **` is no longer accepted as a simple string parameter. It
  satisfied a `pointer_depth >= 1` test, and the harness then passed a
  `char *` where a `char **` was expected -- a mismatch that produces a
  compiler warning rather than a refusal, so a crash afterwards would have
  been an artefact of the harness.
- Git detection in the test suite uses `shutil.which`. `which` is a Unix
  utility whose absence raised `FileNotFoundError` at import time on
  Windows, aborting collection of the whole suite.
- Added an `augur` console script, a GitHub Actions workflow that fails
  when the sanitizer-backed tests are skipped rather than reporting a
  green run, and caching of the per-commit source-diff view.

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

**Harness correctness:** Clang AST extraction is now preferred for C/C++
function boundaries, with the conservative brace matcher retained as an
explicit fallback. Sanitizer attributes are removed before generating the
test harness so a source-level `no_sanitize("address")` annotation cannot
silently disable the ASan evidence path.

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

### Measured, not assumed: making the radar usable on a large project

The first quantitative evaluation of this tool, run against eight real clones
(curl 39,975 commits, openssl 41,346, sqlite 32,540, redis 13,319, libtiff,
libpng, jq, zlib) over a 400-commit window, found the radar unusable at its
default setting on at least one of them: openssl produced **138 candidates
from 400 commits, 34.5% of the report**.

The cause was measured rather than guessed. `sensitive_path` fired on 132 of
those 138 candidates -- 96% of the report -- because the keyword `crypto`
matches 642 changed paths in that window: the entire project lives under
`crypto/`. A keyword present in most commits is a fact about the repository's
layout, not evidence about any one commit.

`--discount-common-path-keywords` estimates each path keyword's frequency
within the window being scanned and discounts the ones that match most of
it. Measured effect:

| project | default | discounted | removed |
|---|---:|---:|---:|
| openssl | 34.5% | **8.0%** | 76.8% |
| libpng | 12.8% | 12.8% | 0.0% |
| sqlite | 9.5% | 9.5% | 0.0% |
| redis | 8.8% | 8.8% | 0.0% |
| libtiff | 5.8% | 5.8% | 0.0% |
| curl | 4.8% | 4.8% | 0.0% |
| jq | 1.5% | 1.5% | 0.0% |
| zlib | 1.0% | 1.0% | 0.0% |

It removed 106 of 314 candidates overall and left all 68 high-confidence
findings untouched. That selectivity is the evidence that it is not simply
suppressing everything: seven of eight projects came out bit-identical.

**What this does not establish.** The removed candidates are unknowns, not
known false positives -- no manual review was done on the removed set, so it
is unknown whether a real silent fix was among them. The two frequency marks
are a calibration over eight projects, not a law: a project whose genuinely
security-critical code occupies 30% of its commits will have that keyword
ignored. The flag is off by default so the original baseline stays
comparable.

Full record, including the measured per-keyword frequencies and the
remaining caveats: `benchmarks/project_campaign.json`.

### Further fixes

- The loud-disclosure filter matched `rce` as a raw substring, so ordinary
  English words containing those three letters -- `resource`, `sources`,
  `force` -- made a commit look like a declared security fix and it was
  dropped from the scan. Seven ordinary subjects were checked; four were
  being discarded. Acronyms now match as whole words.
- Fatal signals are graded by cause. `SEGV` and `BUS` are consistent with a
  bad memory access and count as crashes; `FPE`, `ILL`, `ABRT` and `TRAP` are
  not evidence about a copy and are recorded as failures, so a version that
  merely stopped dividing by zero can no longer be reported as a confirmed
  memory-safety fix. A `DEADLYSIGNAL` that names no signal decides nothing.
  This also required checking for `DEADLYSIGNAL` before the generic error
  header, since ASan prints `ERROR: AddressSanitizer: FPE on unknown address`
  on a signal report and the generic pattern filed that as a memory error.
- `git log -p` output is now consumed as a stream. Capturing it whole and
  splitting it held the raw bytes and the split result in memory at once,
  and a 400-commit scan of openssl or sqlite did not return.
- Command-line configuration is validated: `nan` and `inf` thresholds and
  weights are rejected (every comparison against `nan` is False, so a NaN
  threshold silently disabled its tier and still printed a plausible report),
  an unknown signal name is rejected rather than recorded as a weight for a
  signal that never runs, `--limit` must be at least 1, and a medium
  threshold above the high one is refused.
