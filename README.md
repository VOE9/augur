# Augur

Reads the signs in a project's own commit history. Two independent
sections:

```
python3 -m augur radar <path-to-local-clone> [--limit N]
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

## Section 2 — harness

For a narrow, specific class of C/C++ fixes, turns a heuristic flag into
an executable proof instead of a guess.

```
$ python3 -m augur harness \
    --old vulnerable_version.c --new fixed_version.c \
    --function getCrashAddress \
    --seed "#0 0x556ab456789a in vulnerable_func crash.c:100:5" \
    --param index=0

[*] verdict: confirmed_regression_fix
[*] old crashes at truncation length 3 (heap-buffer-overflow); new runs cleanly at the same length
```

What it does, mechanically:

1. Extracts the named function's full body from both source files (brace
   matching, not a real C parser).
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

### The `--seed` argument, and why it's required, not derived

Augur does not try to reverse-engineer what a "matching" input string
looks like for an arbitrary function (e.g., what prefix format a
`strstr()` call is searching for). That's specific business logic every
function encodes differently, and guessing at it generically is exactly
the kind of over-claiming this project's own convention (see every prior
tool's README) argues against. Instead, you supply **one realistic,
full-length example value** — an actual sample log line, report string,
whatever the function is meant to consume — and Augur automatically
tries every truncation of it, from full length down to nothing. If the
bug is "not enough bytes remain after some point," some truncation length
will hit it; you don't need to know which one in advance.

### The four verdicts

| Verdict | Meaning |
|---|---|
| `confirmed_regression_fix` | Old crashed at some length under ASan; new ran cleanly at that same length. The strongest thing this tool can say. |
| `no_difference_found` | Old never crashed across the whole sweep — either the seed never reaches the bug, or there isn't one at this shape. |
| `inconclusive` | New *also* crashed at the same length old did — the fix may be incomplete, or (more likely) the harness's assumptions don't hold for this function. Never reported as a silent pass. |
| `needs_manual_review` | The signature isn't simple, no matching parameter, or the narrow memcpy pattern wasn't found. This is the *expected*, common outcome for most real functions — Augur is honest that its scope is narrow, not that most bugs fit it. |

## Install

No third-party runtime dependencies. Needs `git` (for `radar`) and a C
compiler with `-fsanitize=address` support, typically `gcc` or `clang`
(for `harness`) already on the system.

```bash
pip install -r requirements.txt  # pytest, for running the test suite
python3 -m pytest tests/
```

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
