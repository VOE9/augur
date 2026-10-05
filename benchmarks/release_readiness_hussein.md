# Release acceptance proposal — Hussein, 2026-10-02

This is a proposed acceptance plan for Ali to discuss, not evidence that the
project already meets these criteria. The existing zlib samples demonstrate
reproducibility; they do not estimate production accuracy.

## 1. Correctness before widening the detector

- Resolve HUS-009 (disclosure token boundaries) and HUS-010 (legacy merge diffs,
  including a merge whose first-parent diff is empty).
- Keep every reported counterexample as a regression check. Confirm the real
  compiler-backed cases after changes to the detector, generator or verdicts.
- Report an unevaluated run as inconclusive. A fatal signal or runtime startup
  failure needs evidence distinguishing it from the specific memory defect.
- Describe confirmation as evidence for the tested inputs and parameters.
  Absence of an observed error is not a general proof of safety.

## 2. Reproducible evidence for users

Proposed report fields across radar, harness and provenance:

| Field | Acceptance check |
| --- | --- |
| Schema and tool version | A reader can identify the format and implementation. |
| Source identity | Revision and source hashes identify the analyzed versions. |
| Configuration | Scan window, thresholds, seed bytes, parameter values and timeouts are retained. |
| Toolchain | Git/compiler versions and relevant sanitizer options are retained. |
| Run evidence | Successful, failed and error runs are distinguishable; failure reasons are preserved. |
| Scope | Unsupported shapes and input coverage are explicit. |

The current radar JSON has schema/configuration fields. Harness JSON exposes
crash rows but not the entire sweep or failed-run rows. Do not describe all modes
as meeting the table until their outputs have been checked.

## 3. Installation and automation

- Build the distributable from a source snapshot and install it into a fresh
  virtual environment. Run from an unrelated directory so imports cannot pass
  merely because the source checkout is on the Python path.
- Verify `augur --version`, each subcommand's help, and an actual Git scan with
  a strict JSON reader. Include repository paths and metadata containing spaces
  and non-ASCII text.
- Require finite numeric weights/thresholds, valid signal names and a positive
  scan limit. Reject invalid configuration with an actionable CLI error.
- In the dedicated sanitizer CI job, run the relevant suite once and inspect
  machine-readable skip results. Preserve failures from pipelines. A successful
  compiler probe alone does not show that the memory tests actually ran.
- Keep matrix results separate: skipped compiler-backed tests on Windows are
  neither failures nor evidence of working ASan there.

`scripts/check_release_hussein.py` is the offline installation/CLI smoke check.
It uses local build dependencies and temporary directories and publishes nothing.

## 4. Evaluation that can support public claims

Suggested first expansion: at least five independently maintained projects,
50 independently supported positive labels and 50 reviewed negative labels.
These counts are planning targets, not guarantees of statistical reliability.
Choose project windows and review labels before comparing signal variants.

- Keep disclosed corrections as exclusion controls, not pretend silent fixes.
- For each proposed silent sample, record the original message, the actual
  correction, independent evidence and disclosure timeline. If timing is unknown,
  mark it unknown instead of claiming silence.
- Review all top-k predictions in selected windows, or use a predeclared sampling
  plan. Record unknown predictions explicitly; absence of a CVE is not a negative.
- Keep tuning projects/windows separate from the final evaluation set.
- Report recall denominators, precision coverage, top-k yield and per-project
  results together. Measure time and work required for a human to investigate.
- Retain default as a baseline until an experimental variant improves a held-out
  evaluation at an agreed review budget. Select success thresholds before tuning.

## 5. Development division and next decision

Ali retains ownership of core implementation, CI and main documentation.
Hussein owns independent counterexamples, regression checks, benchmark tooling
and release smoke tooling. New parser/dataflow or scoring changes need a concrete
failure example and an evaluation plan before adding implementation complexity.

After correctness and installation gates pass, discuss which additional real
projects to label and how much review effort to allocate. Public release claims
must follow the evidence; popularity or broader language support is not itself
a measure of correctness.
