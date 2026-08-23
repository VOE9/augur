"""Augur: reads the signs in a project's own commit history.

Two stages, run independently:
  - radar   -- flags commits that look like an undisclosed ("silent")
               security fix, using the same heuristic signals proven out
               in this portfolio's silent-patch-finder tool.
  - harness -- for a narrow, detectable class of C/C++ fixes (a single
               function, primitive-typed parameters), automatically
               builds a differential AddressSanitizer harness comparing
               the pre-fix and post-fix function bodies, to turn a
               heuristic flag into an executable proof instead of a
               guess. Anything outside that narrow shape is honestly
               reported as needing manual review, not silently skipped.
               For a common bug shape, the seed value itself is derived
               mechanically from the function's own source -- see
               augur.pattern.format_string_prefix.
  - provenance -- for the same narrow bug shape, finds the commit that
               first introduced the vulnerable pattern (structurally,
               not "last commit that touched the line" like classic
               SZZ) and maps it to the tagged versions that actually
               contain it, instead of trusting a hand-written
               advisory's version range.
"""

__version__ = "0.3.0"
