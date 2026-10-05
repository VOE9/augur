# Radar evaluation (Hussein)

`scripts/benchmark_radar.py` evaluates a fixed history window against explicit,
reviewed commit labels. It has no third party runtime dependency and needs Python
3.10+ and git. It reads the original messages and uses the actual Radar engine.
The example contains two separate pinned windows from the same project. The first positive is verified against the
[zlib maintainer's fix commit](https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1),
which describes a buffer-overflow correction for gzip header handling, identified
as CVE-2022-37434 by the [official release notes](https://github.com/madler/zlib/releases/tag/v1.2.13).
The second positive is a [deflate out-of-bound access fix](https://github.com/madler/zlib/commit/5c44459c3b28a9bd3283aaceab7c615f8020c531).
The current disclosure filter matches `rce` inside its word `forces`; this is an
exclusion control illustrating why filter output is not proof of real disclosure.
These are reproducible smoke samples, **not** a representative benchmark or a precision dataset.

From the project root, prepare a **new** full clone once (network access):

```powershell
git clone --no-checkout https://github.com/madler/zlib.git local-clones/zlib
python scripts/benchmark_radar.py benchmarks/radar_manifest.example.json --limit 200 --variant default --min-score 0 --top-k 10 --out radar-default.json
python scripts/benchmark_radar.py benchmarks/radar_manifest.example.json --limit 200 --variant memory-safety --min-score 0 --top-k 10 --out radar-memory.json
```

Preparation is explicit; the benchmark never fetches or accesses the network.
Existing local clones can be used by changing only the manifest `path`, relative
to its directory. The tool makes a disposable clone with independent objects and
sets only its scratch HEAD to the pinned commit. It does not checkout, fetch,
alter config, or modify the supplied clone. Full history is required; shallow
clones are rejected. A missing local path or pinned revision fails the run rather
than fabricating a score. Local working-tree modifications are not evaluated.

Manifest schema 1 requires unique repository names, full lowercase commit SHAs
for `revision` and every label, and `label` of `security_fix` or `non_security`.
Every label needs `evidence` explaining its independent review. Extra fields such
as advisory URLs, reviewer, and review date are retained in the report. Duplicate
SHA labels, including conflicting ones, are rejected. `non_security` means a
reviewed negative **for this task**, never merely absence of a CVE. Labels are
never inferred from Radar scores. Add diverse projects and reviewed negative
samples before interpreting results as performance evidence.

The JSON preserves configuration, full window SHAs, manifest/script hashes, Python/git versions,
and hashes of the exact Radar Python sources (including any uncommitted changes).
Source hashes are captured at import, scan start, and scan end. If
`source_changed_during_run` is true, a concurrent edit invalidates exact source
reproduction; repeat after edits finish. Absence of a detected edit does not
protect against an external edit immediately reverted between snapshots.
Candidates sort by score descending, then SHA ascending on ties. `rank` is the
one-based rank among all qualifying candidates before `--min-score`; `detected`
means the candidate passes the cutoff, and `detected_at_k` means it is in the first
`--top-k` selected candidates. Scores and signal evidence accompany predictions.
`--limit` and `--top-k` must be positive; the cutoff must be finite. Score cutoffs
and variants must be chosen before looking at evaluation labels, or tuned on a
separate training set, to avoid overstating results.

Metrics are reported per repository to avoid concealing differences in windows:

| Field | Meaning |
| --- | --- |
| `eligible_recall` | Detected / known in-window positives that pass intentional message/type exclusions. |
| `eligible_recall_at_k` | Eligible positives found in the first k selected candidates / eligible positives. |
| `eligible_false_negatives` | Eligible in-window positive labels missed at the cutoff. |
| `all_in_window_positive_detection_rate` | Includes intentionally excluded positives; this is not silent-fix recall. |
| `excluded_positives` | In-window positives excluded by loud disclosure or non-fix conventional types. |
| `loud_disclosure_positives` | Positive messages matching the engine's security disclosure keywords. |
| `out_of_window_or_unavailable_positives` | Positives absent from this window; excluded from recall denominators and FN. |
| `labeled_precision` | TP / (TP + FP) among explicitly reviewed predictions only. |
| `reviewed_prediction_coverage` | Reviewed predictions / all predictions. |
| `precision` | Defined only when **every** prediction has a reviewed label, with a nonempty prediction set; otherwise JSON `null`. |

Zero denominators produce `null`, not zero or a claim of perfect performance.
Per-label `availability` distinguishes `out_of_window` from `object_unavailable`;
neither becomes a false negative. A full clone still may lack an orphaned label
commit not reachable from its refs. Per-label exclusions reflect the *current
engine rules*, not an assertion that every remaining fix was truly undisclosed.
Inspect the full original message and publication timeline before calling a
sample a silent fix. This tool does not neutralize disclosure messages; any future
experiment that does so must be reported separately from original-message results.

Only known positives cannot establish recall for all real fixes, and reviewed
subset precision can be biased by which candidates were reviewed. Neither the
one-positive example nor synthetic tests estimate production precision/recall.
Compare variants on identical pinned windows, with explicit coverage and
independent label review, rather than treating unknown candidates as negatives.

Focused offline verification:

```powershell
python -m pytest -q tests/test_radar_benchmark_hussein.py
```

`radar_smoke_results.json` records a real disposable full-clone run on 2026-10-02
at both pinned revisions, with original commit messages and 200-commit windows:

| Fix window | Default | Memory-safety experiment |
| --- | --- | --- |
| `eff308af` (gzip header overflow) | Missed; 15 predictions | Found at rank 32, score 2.0; 60 predictions, 59 unreviewed; outside top 10 |
| `5c44459c` (deflate bounds) | Excluded by `rce` in `forces`; 12 predictions | Same exclusion; 53 predictions |

Full precision is undefined in every saved result. The experiment's labeled
precision of 1 for `eff308af` describes **one reviewed prediction**, with coverage
1/60. The saved smoke runs preceded import/start/end fingerprint instrumentation;
their recorded source hashes were captured after scanning, so they do not prove
the absence of concurrent source changes. Re-run the final CLI for that check.
