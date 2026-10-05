"""Independent benchmark contracts with controlled real git histories."""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_radar.py"
spec = importlib.util.spec_from_file_location("benchmark_radar_hussein", SCRIPT)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git required")


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def commit(repo, filename, text, message):
    (repo / filename).write_text(text, encoding="utf-8")
    git(repo, "add", "--", filename)
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def label(sha, kind="security_fix"):
    return {"sha": sha, "label": kind, "evidence": "Controlled synthetic fixture: independent scenario labels"}


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Benchmark Fixture")
    git(repo, "config", "user.email", "fixture@example.com")
    commit(repo, "auth.py", "def check(x):\n    return True\n", "initial")
    outside = commit(repo, "auth.py", "def check(x):\n    return validate(x)\n", "fix authentication")
    silent = commit(repo, "auth.py", "def check(x):\n    return validate(x) and validate_permission(x)\n", "minor change")
    loud = commit(repo, "auth.py", "def check(x):\n    return validate(x) and validate_permission(x) and validate_token(x)\n", "security fix CVE-2026-0001")
    negative = commit(repo, "auth.py", "# code formatting\n" + (repo / "auth.py").read_text(), "format code")
    unknown = commit(repo, "auth.py", "# release annotation\n" + (repo / "auth.py").read_text(), "annotate module")
    labels = [label(outside), label(silent), label(loud), label(negative, "non_security")]
    return repo, {"name": "fixture", "path": str(repo), "revision": unknown, "labels": labels}, silent, loud, outside


def run(spec, limit=4, variant="default", cutoff=0):
    return benchmark.benchmark_repository(spec, Path.cwd(), limit=limit,
                                         variant=variant, min_score=cutoff, top_k=1)


def test_incomplete_labels_exclusions_window_and_rank(history):
    repo, spec, silent, loud, outside = history
    # Dirty worktree and a different current HEAD must both survive evaluation.
    git(repo, "checkout", "--detach", outside)
    (repo / "untracked.txt").write_text("preserve me")
    (repo / "auth.py").write_text("# locally edited, preserve me\n")
    before = (git(repo, "rev-parse", "HEAD"), git(repo, "status", "--porcelain"))
    report = run(spec)
    metrics = report["metrics"]
    assert metrics["window_commits"] == 4
    assert metrics["predictions"] == 3
    assert metrics["eligible_positives"] == 1
    assert metrics["eligible_recall"] == 1
    assert metrics["eligible_recall_at_k"] == 1
    assert metrics["eligible_false_negatives"] == 0
    assert metrics["excluded_positives"] == 1
    assert metrics["loud_disclosure_positives"] == 1
    assert metrics["all_in_window_positive_detection_rate"] == 0.5
    assert metrics["out_of_window_or_unavailable_positives"] == 1
    assert metrics["reviewed_prediction_tp"] == metrics["reviewed_prediction_fp"] == 1
    assert metrics["unreviewed_predictions"] == 1
    assert metrics["labeled_precision"] == 0.5
    assert metrics["reviewed_prediction_coverage"] == pytest.approx(2 / 3)
    assert metrics["precision"] is None
    rows = {row["sha"]: row for row in report["labels"]}
    assert rows[silent]["rank"] == 1
    assert rows[loud]["exclusion"] == "loud_disclosure"
    assert rows[outside]["availability"] == "out_of_window"
    assert before == (git(repo, "rev-parse", "HEAD"), git(repo, "status", "--porcelain"))
    assert (repo / "untracked.txt").read_text() == "preserve me"
    assert (repo / "auth.py").read_text() == "# locally edited, preserve me\n"


def test_cutoff_has_real_false_negative_and_empty_precision(history):
    report = run(history[1], cutoff=100)
    assert report["metrics"]["eligible_false_negatives"] == 1
    assert report["metrics"]["eligible_recall"] == 0
    assert report["metrics"]["precision"] is None
    # The positive qualified before filtering: preserve its score/rank as evidence.
    assert report["labels"][1]["rank"] == 1
    assert report["labels"][1]["detected"] is False


def test_full_precision_requires_fully_reviewed_predictions(history):
    metrics = run(history[1], cutoff=5)["metrics"]
    assert metrics["predictions"] == 1
    assert metrics["reviewed_prediction_coverage"] == 1
    assert metrics["precision"] == metrics["labeled_precision"] == 1


def test_only_excluded_positives_have_undefined_eligible_recall(history):
    spec = {**history[1], "labels": [label(history[3])]}
    metrics = run(spec)["metrics"]
    assert metrics["excluded_positives"] == 1
    assert metrics["eligible_recall"] is None
    assert metrics["eligible_false_negatives"] == 0


def test_shallow_source_rejected(tmp_path, history):
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "--depth=1", "--no-checkout", history[0].as_uri(), str(shallow))
    spec = {**history[1], "path": str(shallow)}
    with pytest.raises(ValueError, match="full history required"):
        run(spec)


def test_unavailable_positive_is_not_false_negative(history):
    history[1]["labels"].append(label("f" * 40))
    report = run(history[1])
    assert report["labels"][-1]["availability"] == "object_unavailable"
    assert report["metrics"]["out_of_window_or_unavailable_positives"] == 2
    assert report["metrics"]["eligible_false_negatives"] == 0


def test_memory_variant_preserves_baseline_difference(history):
    repo, spec, *_ = history
    sha = commit(repo, "copy.c", "void copy(int len) {\n    if (len > 8) return;\n}\n", "bound copy")
    spec = {**spec, "revision": sha, "labels": [label(sha)]}
    baseline = run(spec, limit=1)
    experimental = run(spec, limit=1, variant="memory-safety")
    assert baseline["metrics"]["eligible_recall"] == 0
    assert experimental["metrics"]["eligible_recall"] == 1
    assert experimental["predictions"][0]["commit"]["sha"] == sha


@pytest.mark.parametrize("kind", ["security_fix", "non_security"])
def test_duplicate_and_conflicting_labels_rejected(tmp_path, history, kind):
    spec = history[1]
    spec["labels"].append(label(spec["labels"][0]["sha"], kind))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "repositories": [spec]}))
    with pytest.raises(ValueError, match="duplicate/conflicting"):
        benchmark.load_manifest(manifest)


@pytest.mark.parametrize("option,value", [("--limit", "0"), ("--limit", "-2"),
                                          ("--top-k", "0"), ("--min-score", "nan"),
                                          ("--min-score", "inf")])
def test_invalid_cli_numbers_fail_before_repository_access(option, value):
    with pytest.raises(SystemExit) as error:
        benchmark.main(["missing.json", option, value])
    assert error.value.code == 2


def test_cli_report_is_pinned_and_fingerprinted(tmp_path, history):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "repositories": [history[1]]}))
    output = tmp_path / "result.json"
    assert benchmark.main([str(manifest), "--limit", "4", "--out", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["experiment"] == "original_commit_messages"
    assert report["repositories"][0]["revision"] == history[1]["revision"]
    assert len(report["manifest_sha256"]) == 64
    assert "engine.py" in report["radar_source_sha256"]


def test_concurrent_source_change_is_reported(tmp_path, history, monkeypatch):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "repositories": [history[1]]}))
    output = tmp_path / "result.json"
    original = benchmark.radar_source_fingerprints()
    changed = {**original, "engine.py": "0" * 64}
    snapshots = iter([original, changed])
    monkeypatch.setattr(benchmark, "radar_source_fingerprints", lambda: next(snapshots))
    assert benchmark.main([str(manifest), "--limit", "4", "--out", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["source_changed_during_run"] is True
    assert report["radar_source_sha256"] == original
    assert report["radar_source_sha256_end"] == changed
