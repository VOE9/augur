# Methodology

## Why radar's detection logic is ported, not rewritten

`silent-patch-finder` (an earlier tool in this portfolio) already found
and fixed three real false-positive classes during its own development,
against real repositories:

- A translation-only commit (locale JSON updated via Crowdin) flagged
  "high confidence" purely because words like "escape" and "permission"
  appear as ordinary, correctly translated UI text — not code. Fixed by
  restricting content signals to a fixed set of source-code extensions.
- A generic path keyword ("proxy") flagged nearly every commit in a
  codebase organized entirely around proxying. Fixed by splitting
  sensitive-path keywords into "strong" (fires alone) and "weak"
  (needs a second, independent weak match to count).
- A brand-new Kubernetes API handler flagged as a "silent fix" purely
  because new endpoints naturally ship with their own new authorization
  checks. Fixed by excluding commits explicitly typed `feat:`/`feature:`
  from the flagship vague-message signal.

Re-deriving this logic from scratch for Augur, even with good intentions,
risks silently reintroducing exactly these three already-solved
problems. Every keyword list, weight, and threshold in `augur/radar/` is
copied unchanged from `silent-patch-finder`'s already-debugged version.

## A gap found and fixed while porting, not present in the original scope

While building Augur's own integration test against a real git repo
(three synthetic commits: a silent fix, a loudly-disclosed fix, and a
`feat:`-typed commit with a defensive-shaped diff), the `feat:` commit
qualified anyway. Tracing why: the ported exclusion only gated the
*vague_message_defensive_diff* signal specifically. `sensitive_path` and
`defensive_diff_shape` are independently qualifying signals (either one
alone is enough to include a commit in the report, per
`QUALIFYING_SIGNAL_NAMES`) — so a `feat:` commit touching a sensitive
path with a defensive-shaped diff still qualified through those two,
regardless of its type.

This isn't a new signal shape; it's the same reasoning the original
exclusion already states ("nothing prior for it to silently correct")
just not applied at the right layer. Fixed in `RadarEngine.evaluate_commit`
by excluding `feat:`/`feature:`-typed commits before any signal runs at
all, not just from the one signal that originally checked for it. Test:
`test_radar_integration.py`.

## A parsing bug found empirically, not by inspection

The first version of `GitRepository.recent_commits()` put the record
separator (`\x1e`) at the *end* of the pretty-format string. Running it
against a real two-commit repository returned only one commit, with
empty diffs. Tracing the raw `git log -p` output directly (not the
parsed result) showed why: with `-p`, git appends each commit's diff
*after* its own pretty-printed header and *before* the next commit's
header — so a trailing separator lands between one commit's header and
its own diff, and splitting on it pairs each diff with the *following*
commit's header instead of its own. Moving the separator to a *prefix*
on the format string fixes the alignment. A second, related bug (`%B`,
the full commit body, can itself contain newlines, so splitting "header"
from "diff" on the first `\n` would truncate any multi-line commit
message) was caught by inspection while fixing the first one and fixed
the same way: split on the literal `\ndiff --git ` marker instead.

## Function extraction and parser fallback

The harness now asks Clang for an AST JSON dump when the `clang` executable is
available. It uses the AST only to locate the byte range of a real function
definition; it does not treat compiler diagnostics as a vulnerability verdict.
The existing conservative parameter classifier and pattern detector remain the
authority for deciding whether automatic harness generation is supported.

If Clang is unavailable or cannot produce a usable AST, Augur falls back to
the earlier brace-matching extractor. This keeps the fallback explicit and
testable rather than silently claiming that regex extraction is equivalent to
parsing. The RTCON integration test exercises the Clang path against the real
`getCrashAddress` regression, while a dedicated test keeps the fallback path
available for minimal environments.

## Why harness needs a required `--seed`, not an inferred one

An earlier design considered trying to reverse-engineer what "matching"
input a function's own internal search logic expects (e.g., the exact
prefix format a `strstr()` call is looking for), to make the tool fully
hands-off. That is a different, much harder problem — general automatic
fuzz-harness generation is an open research area precisely because it
requires understanding what a function's inputs *mean*, not just their
C type. Requiring one realistic example value and sweeping every
truncation of it sidesteps that problem entirely: it needs no
understanding of the function's internal logic, generalizes to any
function with the same "not enough bytes remain" bug shape, and is
exactly the technique used to hand-verify the real bug this tool was
built to automate (RTCON's `getCrashAddress`, see below).

## Ground truth: validated against a real, previously-verified finding

Rather than inventing a synthetic test case, the harness pipeline's
integration test (`test_harness_pipeline_integration.py`) uses the real
pre-fix and post-fix source of `getCrashAddress()` from
`kaist-hacking/RTCON` PR #2 (merged) — a bug in this same portfolio,
originally hand-verified with a manually written ASan harness. Running
Augur's fully automatic pipeline against the same two function bodies
independently reproduces the same conclusion: the old version crashes
under ASan (heap-buffer-overflow) at truncation lengths 3 through 21 of
a realistic seed string; the new version never crashes across the same
sweep. This is the strongest evidence available that the pipeline
works correctly end to end, since the correct answer was already known
independently before Augur existed.

Three real bugs were found and fixed while building the harness
generator itself, all caught by running it against this real ground
truth rather than by inspection:

1. **Attribute-stripping off-by-one.** `__attribute__((...))` removal
   started counting parenthesis depth from the *second* `(` instead of
   accounting for both already-consumed opening parens from the regex
   match, leaving a stray `)` in the cleaned source and making the
   function-signature regex fail to match at all.
2. **Pointer-to-non-char false positive.** `Parameter.is_primitive()`
   originally ignored `pointer_depth` entirely, so `int *count` was
   misclassified as a synthesizable "simple" parameter — Augur has no
   logic to synthesize a meaningful value for "pointer to a single int"
   (out-param? array? optional?). Fixed by requiring `pointer_depth == 0`
   for `is_primitive()`; only `char*` gets separate, deliberate handling
   via `is_string_like()`.
3. **Identity comparison across two separately-parsed parameter lists.**
   The call-argument builder compared parameter objects with `is`
   instead of by name, so it worked for the old function (whose
   parameter object was the one identity-compared against) but always
   failed for the new one, which is parsed as an entirely separate set
   of `Parameter` instances even when logically identical.
4. **Unescaped control characters in the generated C string literal.**
   The first version of the seed-escaping logic handled backslashes and
   quotes but not newlines — a seed containing a literal `\n` (a
   realistic case; crash reports often end in one) produced an
   unterminated C string literal and a compile error. Fixed with a full
   escaper, plus a `""`-boundary trick after hex escapes specifically
   (C hex escapes consume every following hex-digit character
   greedily, so a literal character right after `\xNN` that happens to
   look like a hex digit would otherwise silently merge into it).

## Closing the `--seed` gap: mechanical derivation, not symbolic execution

The original harness design required a human-supplied realistic example
value for the string parameter, documented as a deliberate limit (see
git history / earlier README revision) rather than something to
generalize away casually. Revisiting it: for the real pattern this tool
targets, the "matching" logic is very often exactly `snprintf` building
a needle from the function's own other parameters, then `strstr`
against the tainted string — RTCON's `getCrashAddress` is a real
instance of this, not a constructed example. `FormatStringPrefixDeriver`
reads that pair directly out of the source and renders the format
string with the caller-supplied concrete parameter values (`--param`),
producing the same prefix a human would have had to know or guess
before. Verified against the same real RTCON ground truth as the rest
of this project: `test_auto_seed_integration.py` confirms the identical
regression-fix verdict with **zero** human-supplied seed content.

**`angr` was installed and evaluated as a path to removing `--seed`
entirely** (full symbolic execution of the compiled binary, treating
the string parameter's content as unconstrained and solving for a
crash-triggering assignment, independent of what specific parsing idiom
the function uses). It was not shipped. Reasoning, stated plainly:
mechanical format-string derivation is a small, auditable, single-pass
text transformation whose correctness is easy to verify by reading it;
a symbolic-execution pipeline correct enough to trust in the
`confirmed_regression_fix` path — handling libc hook fidelity, avoiding
state explosion, and not silently returning a satisfying model that
doesn't actually correspond to the real crash condition — is a
meaningfully larger and riskier undertaking than the time available for
this feature justified. Shipping it half-verified would violate this
project's own standing rule (see the RTCON ground-truth section above:
never claim confirmation without being sure it can't be silently
wrong). Left as a documented next step, not attempted under pressure to
use a specific technique for its own sake.

## Provenance: finding when a vulnerability was actually introduced

`augur/provenance/` answers a different question than radar or harness:
given a fix commit, when was the vulnerable pattern actually introduced,
and which released versions contain it? This targets a real,
unsolved-in-general research problem -- a 2025 paper
("Vulnerability-Affected Versions Identification: How Far Are We?")
documents that existing tools (SZZ-based and ML-based alike) have "low
precision and recall" and don't generalize across projects. Augur
doesn't attempt the general problem either; it targets the same narrow
bug shape the harness module already supports, and answers it precisely
for that shape by re-running the same structural detector
(`UnboundedCopyDetector`) against every historical revision of the
function, walking backward from the fix until the exact shape (same
`dest_size`/`copy_length`, deliberately *not* the same variable names --
see the bug below) stops matching. This is a structural improvement
over classic SZZ, which blames whichever commit last touched a line and
is well known to be fooled by pure reformatting or renaming.

**Validated two ways, not just one:**

1. **Controlled ground truth** (`test_provenance_integration.py`): a real
   git repository built with six commits -- a no-op, the true
   introduction, an unrelated change, a *cosmetic rename* of the tainted
   variable, the true fix, and another unrelated change -- with tags at
   four points. Confirms the tool finds the true introduction commit
   (not the cosmetic-rename commit) and maps exactly the tags that
   should be vulnerable.
2. **Real-world validation** (not in the automated test suite, since it
   needs a live clone): run against the actual `kaist-hacking/RTCON`
   repository, using the real merged fix commit from this project's own
   earlier outreach work (`e8b4127`, PR #2). The tool reported
   `skel/crash.c`'s `getCrashAddress` was vulnerable since the
   repository's very first commit (`3f49a23`). Checked independently by
   hand: `git log --follow -- skel/crash.c` shows exactly two commits
   ever touched that file (the initial commit and the fix), and
   `git show 3f49a23:skel/crash.c` contains the unbounded
   `memcpy(addr, pc, 20)` verbatim. The tool's answer and the manual
   check agree completely.

**A real bug found by the controlled test, not by inspection:** the
first version of `_same_signature()` compared `dest_buffer` and
`source_expr` -- the literal *names* of the destination buffer and
source pointer variables -- as part of what makes two findings "the
same vulnerability." The cosmetic-rename commit in the test fixture
(renaming `pc` to `cursor`, changing nothing else) made the walk stop
early, misreporting the rename commit as the introduction point instead
of walking past it to the true one. Fixed by comparing only
`dest_size`/`copy_length` -- the renaming-independent, semantically
meaningful part of the shape.

**Honest limits:** same narrow bug shape as harness (one string
parameter, one taint hop, fixed-size `memcpy`); a repository with no
tags returns an empty vulnerable-version list rather than guessing at
version numbers; and, like harness, this reads git history and runs
structural pattern matching only -- it does not execute anything.

## Building the SZZ baseline instead of asserting the comparison

Earlier versions of these docs stated that classic SZZ is fooled by a
pure rename while `provenance` is not. That was a reasonable reading of
the literature, but it was an assertion -- nothing in the repository
demonstrated it.

`augur/provenance/szz_baseline.py` closes that gap. It implements
classic B-SZZ directly rather than vendoring an existing package, for
the same reason the radar signals were ported rather than re-derived:
the comparison is only worth something if the thing being compared
against is auditable. The algorithm is small enough to state in full --
for every line the fix removed or changed, `git blame` the fix's parent
revision; report the most recently authored of the blamed commits.

Two implementation details worth recording:

- **Pure additions are reported as unanswerable, not guessed.** A fix
  that only inserts lines gives `git diff --unified=0` a hunk with an
  old-side count of zero, so there is nothing to blame. `ClassicSZZ`
  returns `found=False` with that reason. This is a real, documented
  limitation of B-SZZ, and reproducing it faithfully matters more than
  making the baseline look better than it is.
- **The line ranges come from hunk headers, not from a diff parser.**
  `GitRepository.removed_line_ranges()` reads the `@@ -start,count +...`
  headers of `git diff --unified=0` and skips hunks whose old-side count
  is zero. Blaming is capped at 200 lines per fix so a pathologically
  large hunk cannot turn into hundreds of `git blame` invocations.

The result, run against a real repository whose ground truth is known
by construction (`tests/conftest.py` builds it: B introduces the
pattern, D renames a local variable inside the same function, E fixes
it):

| | reports |
|---|---|
| classic B-SZZ | D -- the rename-only commit |
| augur provenance | B -- the real introduction |

The test asserts `!= B` for the baseline as well as `== D`, so if a
future change accidentally makes B-SZZ correct here, the test fails
loudly rather than silently agreeing with the documentation.

## Scope and responsible use

`radar` only reads local git history — no network calls, no contact
with any hosting platform. `harness` only compiles and runs code you
already have locally, under a sanitizer, in a subprocess with no
special privileges — it does not execute untrusted code from the
network, and the functions it targets are limited by design to ones
with primitive/string parameters only.

## What the literature says this tool can and cannot do

Written after a review pass in which the method was checked against
published results rather than against its own intentions. Numbers below are
from the cited papers, not from measurements of Augur -- Augur has no
quantitative evaluation of its own, and saying otherwise would be exactly
the kind of unsupported claim this document exists to avoid.

### Where this problem sits

Silent vulnerability fixes are an established research area, not a
speculative one. Reported estimates put the share of open-source projects
that fix vulnerabilities without disclosing them at around 25%. The
earliest concrete results are striking: mining Linux kernel history for
commits that cannot be traced to any public development artefact --
Ramsauer et al., "The Sound of Silence" (CCSW 2020) -- recovered 29
commits addressing 12 vulnerabilities, giving a 2-to-179-day window before
public disclosure.

Published datasets exist for exactly this task and are large enough to be
useful for evaluation: PatchDB (~12K security and ~24K non-security
patches across 311 projects), SPI-DB (~25K patches from FFmpeg and QEMU),
the VFFinder dataset (~11K fixing and ~25K non-fixing commits across 507
C/C++ projects), and a 2,251-silent-fix set used by GRAPE.

### The state of the art is not what this tool does

The strongest published methods are learned, structural, and graph-based:

| Method | Representation |
|---|---|
| PatchRNN | commit text + syntactic/semantic code features |
| VFFinder | annotated pre/post ASTs through a graph attention network |
| VulFixMiner | Transformer over commit-level diffs |
| Fixseeker | hunk correlation graphs (caller-callee, data, control, replication) |
| GRAPE | a multi-code-property-graph patch representation |
| SSPCatcher | co-training over commit logs and code changes |

VFFinder reports improvements of 39-83% in precision and 19-148% in recall
over the prior state of the art, and a 2.6x speedup at equal review effort.
PatchRNN's NGINX case study found 10 unannounced security patches (43% of
23 security patches across three releases) with no false positives.

**Augur's Radar is a keyword-and-shape heuristic and is far below that
level.** It is kept, and kept deliberately, for three properties the learned
methods do not offer: every result is a deterministic function of the
commit's own text, so a human can check any single line of a report against
a URL; it runs offline against any local clone with no API, no token, and
no dependency on where the project is hosted; and it has no model, so it
cannot produce a confident claim from a misread.

### A measured reason the single-signal heuristic will miss most fixes

Fixseeker's empirical study of 11,900 vulnerability-fixing commits across
six languages found that **over 70% involve multiple hunks**, and that
inter-hunk correlations (caller-callee dependency, data-flow dependency,
control dependency, pattern replication) are present in **93.03%** of
multi-hunk fixes. It also found multi-hunk fixes disproportionately address
severe vulnerabilities (68.51% critical/high, versus 57.25% for
single-hunk).

This is a structural limit, not a tuning problem: a scorer that reads one
commit's message and one file's diff cannot see a correlation between two
hunks. Radar's recall is bounded by this, and no amount of keyword tuning
removes the bound. Multi-hunk correlation is the single highest-value
direction for improving it.

### What the affected-versions literature says about provenance

The 2025 paper cited elsewhere in this document is real and is accurately
quoted: Chen et al., "Vulnerability-Affected Versions Identification: How
Far Are We?", ASE 2025, arXiv:2509.03876. It builds a benchmark of 1,128
real-world C/C++ vulnerabilities (1,542 patches, 59,187 vulnerable
versions, 132 CWE types) and evaluates 12 tools -- six tracing-based
(VCCFinder, V-SZZ, Lifetime, SEM-SZZ, TC-SZZ, LLM4SZZ) and six
matching-based (ReDeBug, VUDDY, MOVERY, V1SCAN, FIRE, VULTURE).

Findings that bear directly on this module:

- **No tool exceeds 45.0% accuracy** at the vulnerability level; the best,
  VCCFinder, reaches 44.9%. A five-tool voting ensemble reaches 55.0%
  accuracy and 84.8% version-level F1 -- better than any single tool, still
  below 60%.
- **Tracing-based tools fall below 40% accuracy on add-only patches**,
  because blame-based tracing has nothing to trace. Augur's provenance
  inherits this limit exactly: it walks the history of one file for one
  function, so a fix that introduces a brand-new guard without touching
  the vulnerable line is invisible to it, and an add-only fix leaves it
  with no reference point at all. Its honest output in that case is
  "no unguarded copy found in the commit before the fix", not a guess.
- **Only 9.37% of patches are syntactically identical across branches**, so
  any exact-matching approach degrades sharply in multi-branch development
  (VULTURE's F1 drops 31.2%, V-SZZ's accuracy 32.7%).
- **Root causes named by the study:** heuristic over-reliance in tracing,
  insufficient semantic modelling, inflexible matching, and -- directly
  relevant here -- *"inadequate verification mechanisms"*: both families
  "lack robust methods to verify that identified versions actually contain
  vulnerabilities".

That last point is the one Augur's `harness` section answers. It does not
identify affected versions; it takes one specific function and one specific
commit and produces an executable AddressSanitizer differential over a
sweep of inputs, so the claim "this commit fixed a memory-safety defect" is
backed by a run rather than by a heuristic. It is the narrowest and most
verifiable of the three sections by construction, and the only one whose
output is a fact rather than a ranking.

### What the SZZ literature says about the baseline comparison

Numbers worth stating next to the B-SZZ comparison in this repository:

- On a developer-informed oracle of 2,304 referenced bug-fixing commits,
  R-SZZ is the most precise variant at roughly 66-73%, while B-SZZ has the
  best recall at about 69% but precision only around 38-42%. F1 for the
  balanced variants sits near 0.50 (Rosa et al., JSS 2023).
- Evaluated on 76,046 Linux-kernel fix/introduction pairs, all SZZ variants
  land between 0.40 and 0.60 precision and recall with F1 around 0.50;
  **17.47% of bug-fixing commits are "ghost commits"** that SZZ cannot
  resolve at all, and over 13% of bug-introducing commits share no file with
  the fixing commit (Rezk et al., 2023).
- When every SZZ variant failed on non-ghost cases, iteratively extending
  blame through history found the introducing commit in **17.7%** of them;
  of the remainder, 34.6% were reachable in the *function* history and
  27.5% only in the file history. Re-running a structural detector over
  function revisions -- which is what Augur's provenance does -- follows the
  better half of that distribution.
- Known SZZ failure modes explicitly documented in the literature are
  formatting and cosmetic changes, refactoring, and **version-control
  metadata such as merge commits**. The last of these is the reason Radar
  now asks git for merge diffs explicitly: without that, a silent fix
  integrated by merge produces a commit with an empty diff.
- Token-level rather than line-level blame reduces false positives from
  whitespace and formatting changes, at a cost of about 0.081 F1
  (Watanabe et al., 2024).
- Herbold et al. found only about 38% of the lines changed in bug-fixing
  commits were actually needed to fix the bug, which is the concrete form of
  the "tangled commit" problem that inflates SZZ precision problems.

None of the above is a measurement of Augur. It is the external context in
which Augur's own numbers, once they exist, will have to be read.
