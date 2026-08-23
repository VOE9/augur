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

from .harness.pipeline import HarnessPipeline, Verdict
from .radar.engine import RadarEngine
from .radar.repository import GitCommandError, GitRepository


def cmd_radar(args: argparse.Namespace) -> int:
    try:
        repo = GitRepository(args.clone_path)
    except (ValueError, GitCommandError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    print(f"[*] scanning last {args.limit} commit(s) in {args.clone_path}...", file=sys.stderr)
    findings = RadarEngine().scan(repo, limit=args.limit)
    print(f"[*] {len(findings)} commit(s) qualified as possible silent fixes", file=sys.stderr)

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

    with tempfile.TemporaryDirectory() as tmp:
        try:
            result = HarnessPipeline().analyze(
                old_source=old_source,
                new_source=new_source,
                function_name=args.function,
                seed=args.seed,
                other_param_defaults=other_defaults,
                workdir=Path(tmp),
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="augur",
        description="Reads the signs in a project's commit history: flags likely undisclosed security fixes, "
                     "and where possible, proves the ones that fit a narrow, checkable pattern.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_radar = sub.add_parser("radar", help="scan a local git clone for possible silent security fixes")
    p_radar.add_argument("clone_path", type=Path, help="path to an existing local git clone")
    p_radar.add_argument("--limit", type=int, default=200, help="how many recent commits to scan (default 200)")
    p_radar.add_argument("--out", type=Path, default=None)
    p_radar.set_defaults(func=cmd_radar)

    p_harness = sub.add_parser("harness", help="attempt an automatic differential ASan proof for one C function")
    p_harness.add_argument("--old", type=Path, required=True, help="source file containing the pre-fix version")
    p_harness.add_argument("--new", type=Path, required=True, help="source file containing the post-fix version")
    p_harness.add_argument("--function", required=True, help="name of the function to compare")
    p_harness.add_argument("--seed", required=True, help="a realistic full-length example value for the string parameter")
    p_harness.add_argument("--param", action="append", default=[], help="name=value for every other parameter, repeatable")
    p_harness.add_argument("--out", type=Path, default=None)
    p_harness.set_defaults(func=cmd_harness)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
