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

## Scope and responsible use

`radar` only reads local git history — no network calls, no contact
with any hosting platform. `harness` only compiles and runs code you
already have locally, under a sanitizer, in a subprocess with no
special privileges — it does not execute untrusted code from the
network, and the functions it targets are limited by design to ones
with primitive/string parameters only.
