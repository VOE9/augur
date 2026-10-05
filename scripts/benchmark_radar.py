"""Offline, pinned-revision evaluation of Radar against explicitly reviewed labels."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def radar_source_fingerprints() -> dict[str, str]:
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((PROJECT_ROOT / "augur" / "radar").glob("*.py"))}


# CLI imports and scanning should use the same source snapshot. Concurrent edits
# invalidate that claim and are exposed explicitly rather than hidden by a final hash.
RADAR_SOURCE_AT_IMPORT = radar_source_fingerprints()

from augur.radar.engine import RadarEngine
from augur.radar.repository import GitRepository
from augur.radar.signal import MemorySafetyDiffSignal, NON_FIX_CONVENTIONAL_TYPES, is_loudly_disclosed

SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
LABELS = {"security_fix", "non_security"}


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise argparse.ArgumentTypeError("must be finite")
    return number


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    if result.returncode:
        raise ValueError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def load_manifest(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("manifest requires schema_version: 1")
    repositories = data.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("manifest requires a nonempty repositories list")
    names = set()
    for repo in repositories:
        if not isinstance(repo, dict):
            raise ValueError("repository entry must be an object")
        name = repo.get("name")
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ValueError("repository names must be unique, nonempty strings")
        names.add(name)
        if not isinstance(repo.get("path"), str) or not repo["path"].strip():
            raise ValueError(f"{name}: requires a local clone path")
        if not isinstance(repo.get("revision"), str) or not SHA_RE.fullmatch(repo["revision"]):
            raise ValueError(f"{name}: revision must be a full lowercase commit SHA")
        labels = repo.get("labels")
        if not isinstance(labels, list) or not labels:
            raise ValueError(f"{name}: requires a nonempty labels list")
        seen = set()
        for entry in labels:
            if not isinstance(entry, dict):
                raise ValueError(f"{name}: label must be an object")
            sha = entry.get("sha")
            if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
                raise ValueError(f"{name}: label SHA must be a full lowercase commit SHA")
            if sha in seen:
                raise ValueError(f"{name}: duplicate/conflicting label for {sha}")
            seen.add(sha)
            if entry.get("label") not in LABELS:
                raise ValueError(f"{name}: label must be security_fix or non_security")
            evidence = entry.get("evidence")
            if not isinstance(evidence, str) or not evidence.strip():
                raise ValueError(f"{name}: every label requires review evidence")
    return data


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate_window(commits: list, labels: list[dict], engine: RadarEngine,
                    min_score: float, top_k: int) -> dict:
    """Unknown commits never become negatives; excluded positives are not eligible FN."""
    # Older git's merge-log fallback can repeat SHAs; count one prediction per commit.
    unique = {commit.sha: commit for commit in reversed(commits)}
    commits = list(reversed(list(unique.values())))
    window = {commit.sha: commit for commit in commits}
    candidates = [finding for commit in commits
                  if (finding := engine.evaluate_commit(commit)) is not None]
    # A SHA tie-break makes ranking reproducible even when git's order ties on timestamps.
    candidates.sort(key=lambda finding: (-finding.score, finding.commit.sha))
    rank = {finding.commit.sha: i for i, finding in enumerate(candidates, 1)}
    scores = {finding.commit.sha: finding.score for finding in candidates}
    selected = [finding for finding in candidates if finding.score >= min_score]
    predicted = {finding.commit.sha for finding in selected}
    predicted_top = {finding.commit.sha for finding in selected[:top_k]}
    label_map = {entry["sha"]: entry for entry in labels}
    rows = []
    for entry in labels:
        sha = entry["sha"]
        commit = window.get(sha)
        exclusion = None
        if commit is not None:
            if is_loudly_disclosed(commit):
                exclusion = "loud_disclosure"
            elif commit.conventional_type() in NON_FIX_CONVENTIONAL_TYPES:
                exclusion = "non_fix_conventional_type"
        rows.append({
            **entry, "in_window": commit is not None,
            "exclusion": exclusion, "rank": rank.get(sha), "score": scores.get(sha),
            "detected": sha in predicted, "detected_at_k": sha in predicted_top,
        })
    positives = [row for row in rows if row["label"] == "security_fix"]
    in_window = [row for row in positives if row["in_window"]]
    eligible = [row for row in in_window if row["exclusion"] is None]
    reviewed_predictions = [label_map[sha] for sha in predicted if sha in label_map]
    tp = sum(entry["label"] == "security_fix" for entry in reviewed_predictions)
    fp = len(reviewed_predictions) - tp
    unknown = len(predicted) - len(reviewed_predictions)
    metrics = {
        "window_commits": len(window), "candidates_before_cutoff": len(candidates),
        "predictions": len(predicted), "known_positives": len(positives),
        "in_window_positives": len(in_window),
        "out_of_window_or_unavailable_positives": len(positives) - len(in_window),
        "excluded_positives": len(in_window) - len(eligible),
        "loud_disclosure_positives": sum(row["exclusion"] == "loud_disclosure" for row in in_window),
        "eligible_positives": len(eligible),
        "eligible_true_positives": sum(row["detected"] for row in eligible),
        "eligible_false_negatives": sum(not row["detected"] for row in eligible),
        "eligible_recall": ratio(sum(row["detected"] for row in eligible), len(eligible)),
        "eligible_recall_at_k": ratio(sum(row["detected_at_k"] for row in eligible), len(eligible)),
        "all_in_window_positive_detection_rate": ratio(sum(row["detected"] for row in in_window), len(in_window)),
        "reviewed_prediction_tp": tp, "reviewed_prediction_fp": fp,
        "unreviewed_predictions": unknown,
        "reviewed_prediction_coverage": ratio(len(reviewed_predictions), len(predicted)),
        "labeled_precision": ratio(tp, tp + fp),
        "precision": ratio(tp, len(predicted)) if unknown == 0 else None,
    }
    return {"metrics": metrics, "labels": rows,
            "predictions": [{"rank": rank[f.commit.sha], **f.to_dict()} for f in selected]}


def benchmark_repository(spec: dict, manifest_directory: Path, *, limit: int,
                         variant: str, min_score: float, top_k: int) -> dict:
    source = (manifest_directory / spec["path"]).resolve()
    if not source.is_dir() or not (source / ".git").exists():
        raise ValueError(f"{spec['name']}: local git clone unavailable at {source}")
    # Never checkout, fetch, or write config in the user's existing clone.
    with tempfile.TemporaryDirectory(prefix="augur-radar-benchmark-") as scratch:
        destination = Path(scratch) / "repo"
        git(Path(scratch), "clone", "--no-hardlinks", "--no-checkout", "--", str(source), str(destination))
        if git(destination, "rev-parse", "--is-shallow-repository") == "true":
            raise ValueError(f"{spec['name']}: full history required; shallow clones are not reproducible windows")
        revision = git(destination, "rev-parse", "--verify", f"{spec['revision']}^{{commit}}")
        if revision != spec["revision"]:
            raise ValueError(f"{spec['name']}: revision must identify a commit, not a tag object")
        # A checkout is unnecessary: Radar only reads history; update only scratch HEAD.
        git(destination, "update-ref", "--no-deref", "HEAD", revision)
        repo = GitRepository(destination)
        commits = repo.recent_commits(limit=limit)
        engine = RadarEngine() if variant == "default" else RadarEngine(
            extra_signals=[MemorySafetyDiffSignal()],
            qualifying_signal_names={MemorySafetyDiffSignal.name},
        )
        report = evaluate_window(commits, spec["labels"], engine, min_score, top_k)
        for row in report["labels"]:
            if row["in_window"]:
                row["availability"] = "in_window"
                continue
            try:
                resolved = git(destination, "rev-parse", "--verify", f"{row['sha']}^{{commit}}")
                row["availability"] = "out_of_window" if resolved == row["sha"] else "not_commit"
            except ValueError:
                row["availability"] = "object_unavailable"
        return {"name": spec["name"], "source_path": str(source), "revision": revision,
                "window_shas": list(dict.fromkeys(commit.sha for commit in commits)), **report}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--limit", type=positive_int, default=200)
    parser.add_argument("--variant", choices=("default", "memory-safety"), default="default")
    parser.add_argument("--min-score", type=finite_float, default=0.0)
    parser.add_argument("--top-k", type=positive_int, default=10)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        source_start = radar_source_fingerprints()
        manifest = load_manifest(args.manifest)
        reports = [benchmark_repository(spec, args.manifest.resolve().parent,
                   limit=args.limit, variant=args.variant, min_score=args.min_score,
                   top_k=args.top_k) for spec in manifest["repositories"]]
        source_end = radar_source_fingerprints()
        report = {
            "schema_version": 1, "experiment": "original_commit_messages",
            "configuration": {"limit": args.limit, "variant": args.variant,
                              "min_score": args.min_score, "top_k": args.top_k,
                              "ranking": "score descending, SHA ascending on ties"},
            "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            "benchmark_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "python_version": sys.version,
            "radar_source_sha256": source_start,
            "radar_source_sha256_at_import": RADAR_SOURCE_AT_IMPORT,
            "radar_source_sha256_end": source_end,
            "source_changed_during_run": source_start != source_end or source_start != RADAR_SOURCE_AT_IMPORT,
            "git_version": git(PROJECT_ROOT, "--version"),
            "repositories": reports,
        }
        output = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        if args.out:
            args.out.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
