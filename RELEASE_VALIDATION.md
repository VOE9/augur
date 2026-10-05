# Local release validation: 0.5.0

Validated on 2026-10-05 against the working tree. Existing development changes
were preserved. No commit or push was performed as part of this verification.

## Results

| Environment/check | Result |
| --- | --- |
| Ubuntu under WSL, Python 3.14.4, full suite including GCC/ASan and Clang | 176 passed, zero skipped |
| Native Windows, Python 3.11.4 | 154 passed, 22 compiler/platform integration tests skipped |
| Guard counterexamples (`scripts/verify_guard_hussein.py --compiler gcc`) | 0 mismatches |
| pyflakes over `augur/`, `scripts/`, `tests/` | Clean |
| Offline wheel build and isolated installation on WSL | 21 checks passed |
| Offline wheel build and isolated installation on Windows | 21 checks passed |
| CI's ten mandatory evidence cases, checked against the WSL JUnit report | Passed; all executed |
| Python 3.10 syntax compatibility | All Python source files parsed successfully |
| Git whitespace validation | Passed |

The isolated installation checks build a wheel from a source snapshot, install
it outside the checkout, verify distribution/CLI versions, exercise console
help, and scan a disposable Git repository with Unicode metadata. Source
hashes were stable during both runs.

The actual `kaist-hacking/RTCON` fix `e8b4127` was also cloned and evaluated
without a manually supplied seed: `confirmed_regression_fix`, with 57 old
error lengths and zero new error lengths. Provenance returned introduction
commit `3f49a23fbde78705edd8c484b6fca2f14d19d782`.

## Regression coverage added

- Conditional loop guards that do not protect the copy.
- Pointer origin before/after assignments, whole identifier matching, and
  pointer equality comparisons.
- Parameter renames, incompatible new signatures, declaration renaming,
  UTF-8 byte sweeps, and embedded NUL refusal.
- Documentation/source diff separation and independent Radar scans.
- C integer formatting and snprintf destination truncation.
- File renames across multiple historical paths and Git worktrees.
- Comment/literal braces and UTF-8/CRLF Clang byte offsets.
- Complete paired sweep evidence, CLI failure messages, source hashes,
  full run statuses, and matching package versions.

## Evidence and remaining verification

Local machine-readable evidence is retained under the ignored
`review-evidence/` directory, with filenames beginning
`release-2026-10-05-`. Local clones, virtual environments and generated logs
are excluded from Git by `.gitignore`.

GitHub Actions is configured for six OS/Python combinations and a dedicated
Linux ASan job. The workflow YAML and evidence gate were checked locally;
the remote matrix still needs to run after the changes are pushed. Python
3.10 syntax validation is not a runtime test on Python 3.10.

These results cover the supported patterns and tested inputs. The detector
remains deliberately narrow, and a confirmed harness result is evidence for
its actual seed, parameters and byte-length sweep.
