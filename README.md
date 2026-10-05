# Augur

Reads the signs in a project's own commit history. Two independent
sections:

```
python3 -m augur radar <path-to-local-clone> [--limit N] [--variant default|memory-safety]
python3 -m augur harness --old OLD.c --new NEW.c --function NAME --seed "..." [--param name=value ...]
```

## Section 1 — radar

Scans a local git clone's recent commits and flags the ones that look
like an undisclosed ("silent") security fix: a commit that touches a
sensitive path or has a defensive-shaped diff (adds a validation call,
removes a dangerous sink), but whose own message never says so.

```
$ python3 -m augur radar ./some-clone --limit 300

### a1b2c3d4e5 — small cleanup
- Author: ... · Confidence: high (score 6.0)
  - sensitive_path (+1.5): 1 file(s) touch sensitive paths (matched: auth)
  - defensive_diff_shape (+1.5): added line(s) call validate
  - vague_message_defensive_diff (+3.0): diff looks defensive but message
    uses a downplaying phrase
```

Works fully offline against any local clone — no GitHub API, no token,
no rate limit, no dependency on the repo being hosted on GitHub at all.
This is a deliberate difference from this portfolio's earlier
`silent-patch-finder`, which needed the GitHub API for PR-association
metadata; Augur drops that one signal in exchange for working on any
repo, anywhere, offline.

The detection logic (keyword lists, signal weights, confidence
thresholds) is ported unchanged from `silent-patch-finder`, not
re-derived — see METHODOLOGY.md for why, and for the real
false-positive classes that logic was already debugged against before
Augur existed.

**Confidence is a reading order, not a verdict.** "High" means "read
this one first." A commit can legitimately show up at "low" confidence
just for touching a path with a sensitive-sounding name — the radar is
broad-recall by design; judgment stays with the human reading the report.

The default Radar is preserved as the reproducible baseline. An opt-in
`memory-safety` variant adds a transparent C/C++ signal for added size,
allocation, copy, and guard/comparison vocabulary:

```
$ python3 -m augur radar ./some-clone --variant memory-safety --limit 300
```

This variant is an experimental candidate-ranking signal, not a proof of a
memory-safety vulnerability. It is deliberately isolated from the default
qualifying signals so baseline comparisons remain valid.

For reproducible experiments, request machine-readable evidence and record
the exact configuration used:

```
$ python3 -m augur radar ./some-clone --limit 300 \
    --format json --out radar-results.json \
    --weight memory_safety_diff=2.0 \
    --high-threshold 5.0 --medium-threshold 2.5
```

The JSON output includes a schema version, every qualified commit's full SHA,
changed files, score, confidence, all signal results, and the active weights
and thresholds. This is intended for benchmark scripts and sensitivity
analysis; it does not turn a heuristic ranking into a vulnerability verdict.

## Section 2 — harness

For a narrow, specific class of C/C++ fixes, turns a heuristic flag into
an executable proof instead of a guess.

```
$ python3 -m augur harness \
    --old vulnerable_version.c --new fixed_version.c \
    --function getCrashAddress --param index=0

[*] no --seed given, attempting automatic prefix derivation...
[*] verdict: confirmed_regression_fix
[*] [auto-derived prefix '#0 '] old crashes at truncation length 3 (heap-buffer-overflow); new runs cleanly at the same length
```

No `--seed` was supplied above — Augur read the function's own `snprintf(...)`/`strstr(...)` logic and derived the exact matching prefix (`"#0 "`) mechanically, then swept truncation lengths against it. `--seed` still exists for functions whose matching logic doesn't fit that shape (see below).

What it does, mechanically:

1. Uses Clang's AST JSON output to locate the named function definition when
   Clang is available, then falls back to conservative brace matching if the
   translation unit cannot be parsed. The existing narrow signature classifier
   still decides whether automatic harness generation is safe.
2. Checks the function's signature is "simple" — every parameter is
   either a primitive scalar (`int`, `size_t`, ...) or a `char*`/`const
   char*` string. Anything else (structs, function pointers, multiple
   string parameters) is refused, not guessed at.
3. Runs a narrow pattern detector: does a fixed-size `memcpy` copy into a
   local buffer from a pointer that traces back to the string parameter
   through simple, single-step pointer arithmetic, with no length check
   in between? This is a single-pass "taint-lite" tracker over exactly
   that statement shape — not general dataflow analysis.
4. If the pattern is found, generates one C file containing both
   function versions (renamed to avoid a symbol clash) and a `main()`
   that truncates a caller-supplied *seed* string to every length from 0
   up to the seed's own length, heap-allocating each truncated candidate
   with **zero slack** past its real end so AddressSanitizer can catch a
   read past it.
5. Compiles with `-fsanitize=address` and runs every (version, length)
   combination as its own subprocess (ASan aborts the whole process on
   the first detected error, so one process per candidate is the only
   reliable way to test many candidates).
6. Reports one of four honest verdicts — see below.

### Automatic prefix derivation, and the honest edge of it

Augur first tries to mechanically read what a "matching" input looks
like straight out of the function's own source: if it finds a
`snprintf(var, len, "format", args...)` call whose result is later
searched for via `strstr(param, var)`, it renders that format string
using the concrete parameter values you passed with `--param`, giving
the exact literal prefix bytes the function's own logic requires — not
a guess, not a reimplementation of the search logic, just the format
string it already contains. It then automatically sweeps every
truncation length after that prefix, the same way a manually-supplied
seed would be swept.

This covers a real, specific shape (`FormatStringPrefixDeriver`,
`augur/pattern/format_string_prefix.py`) — not every function's
matching logic looks like this. When it doesn't (a hand-rolled parsing
loop, a match against a hardcoded byte value, anything without a
`snprintf`-then-`strstr` pair), derivation fails honestly
(`seed_derivation_failed`) and you fall back to `--seed`: supply **one
realistic, full-length example value** yourself, and Augur sweeps every
truncation of it the same way.

**What was deliberately not built:** a general symbolic-execution-based
input solver (via `angr`, installed and evaluated during this feature's
development) that would remove even the `--seed` fallback for arbitrary
matching logic, not just the snprintf/strstr shape. `angr` symbolic
execution of a real compiled binary carries a real, known risk class of
its own — state explosion, subtle setup errors, or an incorrect model
of a hooked libc function silently producing a *wrong* satisfying
input — and this project's standing rule is not to ship anything into
the path that produces a `confirmed_regression_fix` verdict without
being confident it can't be silently wrong. The mechanical derivation
above already closes the practical gap (no human input needed) for a
real, common pattern; a symbolic fallback for the general case is
documented here as a real next step, not attempted under time pressure
just to use a fashionable technique.

### The verdicts

| Verdict | Meaning |
|---|---|
| `confirmed_regression_fix` | Old crashed at one or more lengths under ASan; new crashed at **none** of the swept lengths. The strongest thing this tool can say, and the only verdict that asserts the new version is safe. |
| `partial_fix` | Both crashed, and the new one crashed at lengths the old one also crashed at — or only at lengths the old one survived. The original crash is gone or narrowed, but the new code is still unsafe. |
| `regression_introduced_by_fix` | Old never crashed anywhere in the sweep, new did. The change under test made things worse. |
| `no_difference_found` | Neither implementation crashed across the whole sweep — either the seed never reaches the bug, or there isn't one at this shape. |
| `inconclusive` | At least one input could not be evaluated (timeout, unexplained exit, harness failed to start). **Nothing** is concluded, in particular nothing is confirmed. |
| `needs_manual_review` | The signature isn't a shape Augur can synthesize arguments for, or the tracked copy pattern wasn't found. This is the *expected*, common outcome for most real functions — Augur is honest that its scope is narrow, not that most bugs fit it. |
| `not_found` | The named function could not be located in the given source. |
| `seed_derivation_failed` | (`analyze_auto` / no `--seed` given only) The function's matching logic doesn't fit the snprintf-then-strstr shape automatic derivation needs. Supply `--seed` manually. |

Two things this table is careful about, because both were real defects:

- **`confirmed` means "clean at every length swept", not "clean at the one
  length where old first crashed".** A partially-fixed version that is safe
  for short inputs and still overflows for long ones used to pass as
  confirmed. `tests/test_verdict_correctness.py` carries an ASan-verified
  fixture for exactly that case.
- **A run that could not be evaluated is not a run that passed.** Timeouts,
  unexplained non-zero exits, and harnesses that failed to start all used
  to read as "new did not crash". They now produce `inconclusive`.

A confirmation is still a statement about the inputs that were actually
tested, not about all inputs — one seed, one truncation sweep, one bug
shape. Memory *leaks* are reported separately and never counted as
memory-safety violations, since a function that allocates without freeing
says nothing about whether a copy was bounded.

### What the copy detector covers

`memcpy`, `memmove`, `strcpy`, `strncpy` and `sprintf` into a
fixed-size `char` buffer, from a pointer that traces back to a
caller-supplied string. Copies with a computed length are **not** matched —
`memcpy(buf, q, n)` cannot be judged from the source text alone, and
staying silent is what makes a *fixed* function read as "not found", which
is exactly what stops provenance's backward walk at the fix.

A length comparison counts as a guard only when it can prevent the copy
from running (an early exit, or a clamp). `if (strlen(q) < 16) log();
memcpy(buf, q, 16);` is reported as unguarded.

## Section 3 — provenance

For the same narrow bug shape, answers a different question: given the
fix commit, when was the vulnerable pattern actually introduced, and
which released versions contain it?

```
$ python3 -m augur provenance ./rtcon-clone \
    --file skel/crash.c --function getCrashAddress \
    --fix-commit e8b4127 --param report

[*] found: True
{
  "introduction_commit": "3f49a23...",
  "fix_commit": "e8b4127",
  "vulnerable_tags": [],
  "first_fixed_tag": null
}
```

This targets a real, published research gap: a 2025 paper found that
existing "which versions are affected" tools (SZZ-based and ML-based
alike) have "low precision and recall" and don't generalize across
projects. `provenance` doesn't solve that in general -- it answers it
precisely for the one bug shape it already understands, by re-running
the same structural detector against every historical revision of the
function instead of trusting whichever commit last touched the line
(classic SZZ's well-known weakness: a pure reformatting or renaming
commit gets blamed instead of the real one).

Validated against a real external repository, not just a synthetic
one -- see METHODOLOGY.md for running this against
`kaist-hacking/RTCON`'s actual merged fix and independently confirming
the answer by hand.

An empty `vulnerable_tags` list means either the repository has no
tags, or the introduction/fix commits fall outside all of them --
`provenance` never guesses at version numbers it can't verify against
real tags.

### The SZZ comparison, as something you can run

Claiming "structural beats textual" is easy; the repository now ships
the baseline so the claim can be checked instead of trusted.
`augur/provenance/szz_baseline.py` implements classic B-SZZ (Sliwerski,
Zimmermann & Zeller, 2005) directly -- blame every line the fix removed
or changed, report the most recently authored of those commits.

`tests/test_szz_baseline.py` runs both against the same real git
repository, whose history is built so the answer is known in advance:
commit B introduces the vulnerable pattern, commit D only renames a
local variable inside the same function, commit E is the fix.

```
classic SZZ       -> D    (the rename-only commit)
augur provenance  -> B    (the real introduction)
```

B-SZZ picks D because the rename changed the text of the line the fix
touches, so `git blame` attributes that line to D. `provenance` walks
the same history re-running the structural detector, and the renamed
variable does not change the shape it matches on.

The same test also covers the case B-SZZ genuinely cannot answer: a fix
that only adds lines leaves nothing to blame, and `ClassicSZZ` reports
that rather than guessing.

## Install

No third-party runtime dependencies. Needs `git` (for `radar`) and a C
compiler with `-fsanitize=address` support, typically `gcc` or `clang`
(for `harness`) already on the system. Clang is preferred for AST-based
function extraction; the documented fallback keeps the tool usable when only
GCC is installed.

```bash
python3 -m pip install .        # installs the augur command
pip install -r requirements.txt  # pytest, for running the test suite
python3 -m pytest tests/
```

On Windows, use WSL for the sanitizer-backed harness when a working GCC/ASan
toolchain is not installed natively. Radar and provenance also accept Git
worktrees. All source and report files are read/written as UTF-8.

Manual seeds are UTF-8 strings; truncation lengths count **bytes**. Embedded
NUL bytes are refused because this harness models C strings. Parameter names
may change between versions, but parameter types and positions must remain
compatible. Unsupported signature changes require manual review.

Automatic prefix derivation supports a literal-sized `snprintf` followed by
`strstr`, including C integer literal formatting, escapes, `%%` and byte
truncation to the destination size. Unsupported expressions and prefixes
truncated inside a UTF-8 character require a manual seed.

Before preparing a release, run the suite with an ASan-capable compiler and
verify that an isolated wheel installs and its console commands work:

```bash
python3 -m pytest tests/ -q -rs
python3 scripts/check_release_hussein.py
```

GitHub Actions runs the portable suite on Linux, macOS and Windows, plus a
dedicated Linux job that requires the critical compiler-backed tests to run.
Real LeakSanitizer integration checks run on Linux; leak-output parsing tests
run on every platform.

## Honest limits

- **`radar`'s signals are heuristics, not verdicts** — see the confidence
  note above and METHODOLOGY.md's account of the false positives this
  logic was built to survive.
- **`harness` covers one specific bug shape**: a fixed-size `memcpy` from
  a string parameter, reached through at most one intermediate pointer
  variable. A bug reached through a loop, a helper function call, or
  multiple reassignment steps will not be detected — reported as
  `needs_manual_review`, never silently missed as a false "no bug here."
- **One string parameter, one taint hop.** Functions with two or more
  string-like parameters, or where the tainted pointer passes through
  more than one intermediate variable, are out of scope for the same
  reason: correctly generalizing either would require real dataflow
  analysis, which this tool deliberately does not attempt.
- **This does not fuzz.** The truncation sweep is exhaustive over one
  dimension (string length) for one seed, not a search over arbitrary
  byte content. It will find "too short" bugs; it will not find bugs
  that need specific byte *values*, not just length.
