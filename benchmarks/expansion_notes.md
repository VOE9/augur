# Independent dataset expansion — Hussein, started 2026-10-02; final review 2026-10-03

This adds two independently maintained projects to the known-fix data: curl and
libexpat. The initial additions are **disclosed-fix exclusion controls**. After
scanning libexpat, independent review added one comment-only negative and one
semantically disclosed security-defense positive that the engine accepts. There
are **zero verified silent-fix labels**. This is progress toward
the release evaluation proposal, not completion of its sample or accuracy goals.

Files: `radar_manifest.expansion.json` is schema 1 and can be read by the existing
benchmark CLI; `radar_expansion_results.json` preserves verified source identity,
patch/message hashes, source fingerprints, actual single-commit checks, and clone
preparation status. No existing benchmark, core implementation or test was edited.

## Primary evidence and timeline

| Project | Pinned fix | Evidence and role |
| --- | --- | --- |
| curl | `fb4415d8aee6c1045be932a34fe6107c2f5ed147` | The [project advisory](https://curl.se/docs/CVE-2023-38545.html) identifies this fix for CVE-2023-38545. The [original commit](https://github.com/curl/curl/commit/fb4415d8aee6c1045be932a34fe6107c2f5ed147) includes the CVE link in its body, even though its subject alone does not. Disclosed control. |
| libexpat | `3f0a0cb644438d4d8e3294cd0b1245d0edb0c6c6` | The [original commit](https://github.com/libexpat/libexpat/commit/3f0a0cb644438d4d8e3294cd0b1245d0edb0c6c6) identifies CVE-2022-25235 in its subject. The [official 2.4.5 changelog](https://raw.githubusercontent.com/libexpat/libexpat/R_2_4_5/expat/Changes) describes the correction and security impact. Disclosed control. |
| libexpat | `b1d039607d3d8a042bf0466bfcc1c0f104e353c8` | The [public security PR #466](https://github.com/libexpat/libexpat/pull/466) lists this exact commit and identifies CVE-2013-0340/CWE-776; the [official 2.4.0 changelog](https://raw.githubusercontent.com/libexpat/libexpat/R_2_4_0/expat/Changes) includes PR 466 in the security correction. Original subject explicitly describes attack protection. Semantically disclosed control accepted by the current engine. |

curl's advisory records the report on 2023-09-30, distribution coordination on
2023-10-03, and coordinated public advisory/fixed release on 2023-10-11. Its
[official patch](https://github.com/curl/curl/commit/fb4415d8aee6c1045be932a34fe6107c2f5ed147.patch)
has an author timestamp on 2023-10-11. The public first-visibility time of that
commit was not established; metadata timestamps do not establish publication.

libexpat's
[official patch](https://github.com/libexpat/libexpat/commit/3f0a0cb644438d4d8e3294cd0b1245d0edb0c6c6.patch)
has an author timestamp on 2022-02-08. Its release/changelog is dated 2022-02-18.
The initial private report date, first public disclosure, and first public commit
visibility remain unknown in this review. The ten-day difference is **not**
evidence of a silent public period. The original commit already names the CVE.

For `b1d03960`, Git author/committer dates are 2021-04-19 and 2021-05-07.
PR #466 records security labels/activity on 2021-04-20, the exact commit added on
2021-05-07, and merge on 2021-05-11; the fixed release is dated 2021-05-23.
These dated records establish explicit security context, while an exact initial
public visibility time is not claimed. This additional label was reviewed
**after inspecting the scan output**, and is exploratory, not held out.

The manifest retains original subjects, message disclosure markers, primary
source URLs and reproduction commands. The downloaded patch's leading SHA and
parsed subject were checked against each manifest entry. A normalized original
message was formed from the subject and original message body, excluding the
patch statistics/diff; its SHA-256 is recorded alongside the raw patch hash.
Normalization uses the subject alone when the body is empty, otherwise subject,
two LF characters, and the stripped body, with no final LF. This identifies the
message used for the single-commit check, not a claim about Git object bytes.
The original message is never rewritten or neutralized for scoring.

## What actually ran

Downloaded each official `.patch` over HTTPS and evaluated its original full
message and diff through the actual `RadarEngine`, separately with default and
memory-safety configurations. Both initial commits were loudly disclosed and both engines
excluded them. Import/start/end Radar source fingerprints agreed:
`source_changed_during_run=false` in the saved result. These are **single-commit
exclusion checks**, separate from the completed libexpat history scan.

| Control | Default | Memory-safety | History window/rank |
| --- | --- | --- | --- |
| curl CVE-2023-38545 | Excluded | Excluded | Not executed |
| libexpat CVE-2022-25235 | Excluded | Excluded | In the actual pinned 200-commit window |
| libexpat CVE-2013-0340 defense | Rank 50, score 1.5 | Rank 5, score 3.0 | Same actual 200-commit window |

Full clone preparation was attempted independently into new directories under
`local-clones`, using `--no-checkout --single-branch --no-tags` without a shallow
history. curl exceeded a 240-second timeout and had no resolvable HEAD. libexpat
completed and its HEAD is `a824e920f3d3d77930d7897c80b6925a6733aebc`.
Only child Git processes created by the stalled preparation were stopped.
No existing local clone was changed or replaced. HTTPS patch downloads succeeded;
the failure is specific to this full-clone preparation, not proof that the
projects or patch sources are unavailable. curl's partial directory was left in
place; do not treat it as a valid benchmark input.

The saved history-run status is `partially_executed`: curl `not_executed`, libexpat
`executed`. libexpat scans use revision `3f0a0cb6`, limit 200, cutoff 0 and top-k 10
in disposable copies of the full clone; source import/start/end fingerprints
match. Default produced **65** candidates, memory-safety **68**. The CVE-named
control was excluded in both, as expected.

The attack-defense correction `b1d03960` is admitted by the existing keyword
filter even though its original subject declares protection against an attack.
The variant places it in the first ten candidates; default does not. The output's
`eligible_recall=1` describes eligibility under that filter for this one label,
**not silent-fix recall**. The manifest and result explicitly distinguish human
disclosure classification from engine eligibility. No neutralized-message
experiment was used.

Full precision remains `null`: **63** default and **66** variant predictions
have no independently established label. `labeled_precision=0.5` concerns only
one known positive and one reviewed negative prediction; coverage is 2/65 and
2/68, respectively. Selection after scanning makes this exploratory evidence;
it is not production precision or an unbiased held-out comparison.

## Five manually reviewed baseline predictions

The first five default predictions, under deterministic score/SHA ranking, were
reviewed using full first-parent diffs, including the merge. SHA, changed paths,
raw diff hash, reason and signal evidence are retained in the result.

| Candidate | Review outcome |
| --- | --- |
| `039af6611d0c28e879196698ee0f6707d430d855` | Copyright comments plus installer display-copyright property; retained unknown under the strict comment-only negative rule because a property value changes. |
| `29c3748788ff5ba0e4b14b02dfa15080177a3c8c` | Executable entropy-debug environment handling changes; unknown without independent security/non-security classification. |
| `41b732a16381699e4c9ad831b6fef20c86cf9461` | Merge changes CDATA amplification accounting. Official changelog identifies PR 484 in security work; retained as a security-relevant unknown candidate pending precise classification/timeline review. Empty ordinary git show output was not mistaken for an empty first-parent diff. |
| `5a8f5f1d4017d14a01822b57c089764a5b598a1c` | **Reviewed non_security**: four spelling corrections wholly inside comments across CMake/C source/test files. No executable expression, declaration, literal or build command changes. Full [commit diff](https://github.com/libexpat/libexpat/commit/5a8f5f1d4017d14a01822b57c089764a5b598a1c) is the evidence. |
| `5bab452b4952ab417a0a47ce4a6185e94e22bd0c` | Stack-buffer initialization changes executable behavior. A compiler-warning subject does not establish absence of a security correction; unknown. |

The negative is based on the complete comment-only diff, not absence of a CVE.
The other four remain unlabelled and are included in unknown-prediction counts.

## Reproduction after full clones become available

Prepare **new absent destination paths**. If a failed attempt left an existing
directory, choose another new path and update the manifest's `path`; preserve
other developers' clones. The completed libexpat clone can be used without
replacement. Example preparation for fresh destinations:

```powershell
git clone --no-checkout --single-branch --no-tags https://github.com/curl/curl.git local-clones/curl-expansion-retry
git clone --no-checkout --single-branch --no-tags https://github.com/libexpat/libexpat.git local-clones/libexpat-expansion-retry
```

Set the two manifest paths to the resulting full local clones, retaining pinned
revision/labels, then run from the project root:

```powershell
python scripts/benchmark_radar.py benchmarks/radar_manifest.expansion.json --limit 200 --variant default --min-score 0 --top-k 10 --out radar-expansion-default.json
python scripts/benchmark_radar.py benchmarks/radar_manifest.expansion.json --limit 200 --variant memory-safety --min-score 0 --top-k 10 --out radar-expansion-memory.json
```

For original message inspection, use the full SHA with
`git -C <clone> show -s --format=%B <sha>`; the exact per-project commands are in
the manifest. A cutoff of 0, limit of 200 and review budget of 10 were chosen
before scanning; variants must be compared on the same pinned windows.

## Remaining evidence needed

These additions increase project diversity for exclusion controls, while useful
silent-fix recall and precision data remain missing. Before public performance
claims, establish original-message/publication timelines for proposed silent
positives, choose held-out windows before tuning, and independently review all
top-k predictions or a predeclared sample. Record unknown labels and human review
cost. Neither a later CVE identifier nor an early Git author date proves a fix
was silently published. Broader quantitative claims should wait for those
labels and completed history runs.
