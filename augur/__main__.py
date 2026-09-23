"""
CLI entrypoint — two sections, run independently.

    python3 -m augur radar <path-to-local-clone> [--limit N] [--out FILE]
    python3 -m augur harness --old OLD.c --new NEW.c --function NAME \\
        --seed "..." [--param name=value ...] [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__
from .harness.pipeline import HarnessPipeline, Verdict
from .provenance.pipeline import ProvenancePipeline
from .radar.engine import RadarEngine
from .radar.repository import GitCommandError, GitRepository
from .radar.signal import MemorySafetyDiffSignal


def cmd_radar(args: argparse.Namespace) -> int:
    try:
        repo = GitRepository(args.clone_path)
    except (ValueError, GitCommandError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    print(f"[*] scanning last {args.limit} commit(s) in {args.clone_path}...", file=sys.stderr)
    weights = {}
    for raw_weight in args.weight:
        if "=" not in raw_weight:
            print(f"[!] --weight must be signal=value, got: {raw_weight}", file=sys.stderr)
            return 1
        name, raw_value = raw_weight.split("=", 1)
        try:
            weights[name] = float(raw_value)
        except ValueError:
            print(f"[!] invalid --weight value: {raw_weight}", file=sys.stderr)
            return 1

    if args.variant == "memory-safety":
        engine = RadarEngine(
            extra_signals=[MemorySafetyDiffSignal()],
            qualifying_signal_names={MemorySafetyDiffSignal.name},
            weight_overrides=weights,
            high_threshold=args.high_threshold,
            medium_threshold=args.medium_threshold,
        )
    else:
        engine = RadarEngine(
            weight_overrides=weights,
            high_threshold=args.high_threshold,
            medium_threshold=args.medium_threshold,
        )
    findings = engine.scan(repo, limit=args.limit)
    print(f"[*] {len(findings)} commit(s) qualified as possible silent fixes", file=sys.stderr)

    if args.format == "json":
        report = render_radar_json(
            findings,
            {
                "variant": args.variant,
                "high_threshold": engine.high_threshold,
                "medium_threshold": engine.medium_threshold,
                "weight_overrides": weights,
            },
        )
    else:
        report = render_radar_report(findings)
    if args.out:
        args.out.write_text(report)
        print(f"[*] report written to {args.out}", file=sys.stderr)
    else:
        print("\n" + report)
    return 0


def render_radar_report(findings) -> str:
    lines = ["# Augur radar report", "", f"{len(findings)} commit(s) qualified, ranked by score.", ""]
    for f in findings:
        lines.append(f.to_markdown())
        lines.append("")
    if not findings:
        lines.append("No commits qualified in this range.")
    return "\n".join(lines)


def render_radar_json(findings, configuration: dict | None = None) -> str:
    payload = {
        "schema_version": "1.0",
        "tool": "augur",
        "mode": "radar",
        "qualified_count": len(findings),
        "configuration": configuration or {},
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def cmd_harness(args: argparse.Namespace) -> int:
    other_defaults: dict[str, str] = {}
    for kv in args.param:
        if "=" not in kv:
            print(f"[!] --param must be name=value, got: {kv}", file=sys.stderr)
            return 1
        name, value = kv.split("=", 1)
        other_defaults[name] = value

    old_source = args.old.read_text()
    new_source = args.new.read_text()
    pipeline = HarnessPipeline()

    with tempfile.TemporaryDirectory() as tmp:
        try:
            if args.seed is None:
                print("[*] no --seed given, attempting automatic prefix derivation...", file=sys.stderr)
                result = pipeline.analyze_auto(
                    old_source=old_source, new_source=new_source, function_name=args.function,
                    other_param_defaults=other_defaults, workdir=Path(tmp),
                )
            else:
                result = pipeline.analyze(
                    old_source=old_source, new_source=new_source, function_name=args.function,
                    seed=args.seed, other_param_defaults=other_defaults, workdir=Path(tmp),
                )
        except Exception as e:  # compiler errors, etc. -- surfaced, not swallowed
            print(f"[!] harness pipeline failed: {e}", file=sys.stderr)
            return 1

    print(f"[*] verdict: {result.verdict}", file=sys.stderr)
    print(f"[*] {result.detail}", file=sys.stderr)

    payload = {
        "function": result.function_name,
        "verdict": result.verdict,
        "detail": result.detail,
        "old_crashes": [r.__dict__ for r in result.old_results if r.crashed],
        "new_crashes": [r.__dict__ for r in result.new_results if r.crashed],
    }
    if args.out:
        args.out.write_text(json.dumps(payload, indent=2))
        print(f"[*] result written to {args.out}", file=sys.stderr)
    else:
        print(json.dumps(payload, indent=2))

    return 0 if result.verdict == Verdict.CONFIRMED_REGRESSION_FIX else (1 if result.verdict == Verdict.INCONCLUSIVE else 0)


def cmd_provenance(args: argparse.Namespace) -> int:
    try:
        repo = GitRepository(args.clone_path)
    except (ValueError, GitCommandError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    result = ProvenancePipeline().analyze(
        repo, filename=args.file, function_name=args.function,
        fix_commit=args.fix_commit, tainted_param=args.param,
    )

    payload = {
        "found": result.introduction.found,
        "reason": result.introduction.reason,
        "introduction_commit": result.introduction.introduction_commit,
        "fix_commit": result.introduction.fix_commit,
    }
    if result.version_range:
        payload["vulnerable_tags"] = result.version_range.vulnerable_tags
        payload["first_fixed_tag"] = result.version_range.first_fixed_tag

    print(f"[*] found: {result.introduction.found}", file=sys.stderr)
    print(f"[*] {result.introduction.reason}", file=sys.stderr)

    if args.out:
        args.out.write_text(json.dumps(payload, indent=2))
        print(f"[*] result written to {args.out}", file=sys.stderr)
    else:
        print(json.dumps(payload, indent=2))

    return 0 if result.introduction.found else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="augur",
        description="Reads the signs in a project's commit history: flags likely undisclosed security fixes, "
                     "and where possible, proves the ones that fit a narrow, checkable pattern.",
    )
    parser.add_argument("--version", action="version", version=f"augur {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_radar = sub.add_parser("radar", help="scan a local git clone for possible silent security fixes")
    p_radar.add_argument("clone_path", type=Path, help="path to an existing local git clone")
    p_radar.add_argument("--limit", type=int, default=200, help="how many recent commits to scan (default 200)")
    p_radar.add_argument("--out", type=Path, default=None)
    p_radar.add_argument("--format", choices=("markdown", "json"), default="markdown")
    p_radar.add_argument("--weight", action="append", default=[], help="override a signal weight: signal=value")
    p_radar.add_argument("--high-threshold", type=float, default=RadarEngine.HIGH_THRESHOLD)
    p_radar.add_argument("--medium-threshold", type=float, default=RadarEngine.MEDIUM_THRESHOLD)
    p_radar.add_argument(
        "--variant", choices=("default", "memory-safety"), default="default",
        help="opt-in experimental signal variant; default preserves the original Radar",
    )
    p_radar.set_defaults(func=cmd_radar)

    p_harness = sub.add_parser("harness", help="attempt an automatic differential ASan proof for one C function")
    p_harness.add_argument("--old", type=Path, required=True, help="source file containing the pre-fix version")
    p_harness.add_argument("--new", type=Path, required=True, help="source file containing the post-fix version")
    p_harness.add_argument("--function", required=True, help="name of the function to compare")
    p_harness.add_argument(
        "--seed", default=None,
        help="a realistic full-length example value for the string parameter; "
             "omit to attempt automatic derivation from the function's own source",
    )
    p_harness.add_argument("--param", action="append", default=[], help="name=value for every other parameter, repeatable")
    p_harness.add_argument("--out", type=Path, default=None)
    p_harness.set_defaults(func=cmd_harness)

    p_prov = sub.add_parser("provenance", help="find when a vulnerable pattern was introduced, and which tagged versions contain it")
    p_prov.add_argument("clone_path", type=Path, help="path to an existing local git clone")
    p_prov.add_argument("--file", required=True, help="path to the source file, relative to the repo root")
    p_prov.add_argument("--function", required=True, help="name of the function")
    p_prov.add_argument("--fix-commit", required=True, help="SHA of the commit that fixed the vulnerability")
    p_prov.add_argument("--param", required=True, help="name of the tainted string-like parameter")
    p_prov.add_argument("--out", type=Path, default=None)
    p_prov.set_defaults(func=cmd_provenance)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
