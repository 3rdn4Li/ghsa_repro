from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from .config import load_config
from .doctor import check
from .github import collect_published_year
from .input import SEVERITIES, jsonl, load_input
from .pipeline import AuditPipeline, initialize_run, load_run, monitor, summarize
from .storage import atomic_text


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="ghsa-repro",
        description="Build and run resumable current-upstream GHSA reproduction audits.",
    )
    commands = root.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser(
        "doctor", help="verify configuration, Codex CLI, and model endpoint"
    )
    doctor.add_argument("--config", required=True, type=Path)
    doctor.add_argument("--codex-binary", help="override codex.binary for this check")

    collect = commands.add_parser(
        "collect", help="collect reviewed advisories by publication year"
    )
    collect.add_argument("--year", required=True, type=int)
    collect.add_argument("--severity", choices=sorted(SEVERITIES), default="critical")
    collect.add_argument("--output", required=True, type=Path)
    collect.add_argument("--github-token-env", default="GH_TOKEN")

    validate = commands.add_parser(
        "validate-input", help="validate canonical JSONL or compatible CSV"
    )
    validate.add_argument("input", type=Path)
    validate.add_argument("--assume-severity", choices=sorted(SEVERITIES))
    validate.add_argument("--assume-published-timezone", choices=["UTC"])

    initialize = commands.add_parser("init", help="create an immutable resumable run")
    initialize.add_argument("--input", required=True, type=Path)
    initialize.add_argument("--config", required=True, type=Path)
    initialize.add_argument("--run-dir", required=True, type=Path)
    initialize.add_argument("--assume-severity", choices=sorted(SEVERITIES))
    initialize.add_argument("--assume-published-timezone", choices=["UTC"])
    initialize.add_argument("--target", action="append", default=[])

    reassess = commands.add_parser(
        "init-reassessment",
        help="create an explicit impact reassessment run with frozen prior records",
    )
    reassess.add_argument("--input", required=True, type=Path)
    reassess.add_argument("--config", required=True, type=Path)
    reassess.add_argument("--run-dir", required=True, type=Path)
    reassess.add_argument("--assume-severity", choices=sorted(SEVERITIES))
    reassess.add_argument("--assume-published-timezone", choices=["UTC"])
    reassess.add_argument("--target", action="append", required=True)
    reassess.add_argument(
        "--prior-record-set",
        action="append",
        required=True,
        metavar="LABEL=RECORDS_DIR",
    )

    run = commands.add_parser("run", help="resume pending targets in a run")
    run.add_argument("--run-dir", required=True, type=Path)
    run.add_argument("--jobs", type=int)
    run.add_argument("--timeout-seconds", type=int)
    run.add_argument("--target", action="append", default=[])
    run.add_argument(
        "--acknowledge-local-security-risk",
        action="store_true",
        help="required: agents execute untrusted reproduction work with host access",
    )

    aggregate = commands.add_parser(
        "summarize", help="validate records and regenerate aggregate outputs"
    )
    aggregate.add_argument("--run-dir", required=True, type=Path)

    status = commands.add_parser(
        "monitor", help="print one bounded run-status snapshot"
    )
    status.add_argument("--run-dir", required=True, type=Path)
    return root


def _safe_run_root(value: Path) -> Path:
    resolved = value.resolve()
    if (
        resolved == Path("/")
        or resolved == Path.home().resolve()
        or len(resolved.parts) < 3
    ):
        raise ValueError(f"refusing unsafe run directory: {resolved}")
    return resolved


def _prior_record_sets(values: list[str]) -> dict[str, Path]:
    result = {}
    for value in values:
        label, separator, directory = value.partition("=")
        if not separator or not label or not directory:
            raise ValueError("--prior-record-set must be LABEL=RECORDS_DIR")
        if label in result:
            raise ValueError(f"duplicate prior record label: {label}")
        result[label] = Path(directory)
    return result


def execute(args: argparse.Namespace) -> object:
    if args.command == "doctor":
        config = load_config(args.config)
        if args.codex_binary:
            config = replace(
                config, codex=replace(config.codex, binary=args.codex_binary)
            )
        return check(config)
    if args.command == "collect":
        if args.output.exists():
            raise FileExistsError(f"refusing to overwrite input: {args.output}")
        records = collect_published_year(
            args.year, args.severity, token_env=args.github_token_env
        )
        atomic_text(args.output, jsonl(records), mode=0o644)
        return {
            "output": str(args.output.resolve()),
            "year_basis": "published_at",
            "year": args.year,
            "severity": args.severity,
            "targets": len(records),
        }
    if args.command == "validate-input":
        records = load_input(
            args.input,
            assumed_severity=args.assume_severity,
            assumed_published_timezone=args.assume_published_timezone,
        )
        return {
            "input": str(args.input.resolve()),
            "targets": len(records),
            "valid": True,
        }
    if args.command == "init":
        return initialize_run(
            args.input,
            args.config,
            _safe_run_root(args.run_dir),
            assumed_severity=args.assume_severity,
            assumed_published_timezone=args.assume_published_timezone,
            selected_targets=args.target,
        )
    if args.command == "init-reassessment":
        return initialize_run(
            args.input,
            args.config,
            _safe_run_root(args.run_dir),
            assumed_severity=args.assume_severity,
            assumed_published_timezone=args.assume_published_timezone,
            selected_targets=args.target,
            prior_record_sets=_prior_record_sets(args.prior_record_set),
            run_kind="impact_reassessment",
        )
    paths, config, manifest = load_run(_safe_run_root(args.run_dir))
    if args.command == "run":
        if not args.acknowledge_local_security_risk:
            raise ValueError("run requires --acknowledge-local-security-risk")
        pipeline = AuditPipeline(paths, config, manifest)
        return pipeline.run(
            jobs=args.jobs or config.codex.default_jobs,
            timeout_seconds=args.timeout_seconds or config.codex.timeout_seconds,
            target_ids=args.target,
        )
    if args.command == "summarize":
        return summarize(paths, config)
    if args.command == "monitor":
        return monitor(paths)
    raise AssertionError(args.command)


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        result = execute(arguments)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
