from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .storage import atomic_json, sha256

SHA40 = re.compile(r"^[0-9a-f]{40}$")
CURRENT_STATUSES = {
    "still_present_current_default",
    "partially_fixed_but_same_vulnerability_reachable",
    "fixed_current_default",
    "fixed_default_but_present_on_maintained_release",
    "feature_removed_or_security_boundary_eliminated",
    "different_issue_only",
    "indeterminate",
}
PROOF_LEVELS = {"executable", "static_strong", "static_partial", "indeterminate"}
STILL_PRESENT = {
    "still_present_current_default",
    "partially_fixed_but_same_vulnerability_reachable",
}
FIXED_NOW = {
    "fixed_current_default",
    "feature_removed_or_security_boundary_eliminated",
    "different_issue_only",
}
RECORD_FIELDS = {
    "schema_version",
    "target_id",
    "source",
    "repository",
    "recorded_vulnerable_commit",
    "proposed_fixed_commit",
    "original_exclusion_reason",
    "rejected_candidates",
    "advisory_year_month",
    "audited_at",
    "current_default",
    "maintained_branches_examined",
    "reported_root_cause",
    "attacker_boundary",
    "current_status",
    "proof_level",
    "equivalent_paths_checked",
    "reproduction",
    "current_source_evidence",
    "complete_fix_outside_recorded_descendant_history",
    "earliest_complete_current_fix",
    "artifact_root",
    "reasoning",
}


def nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def parse_envelope(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    candidates = [
        text,
        *re.findall(r"```(?:json)?\s*\n(.*?)```", text, flags=re.DOTALL),
    ]
    for candidate in candidates:
        try:
            value = json.loads(candidate.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError(f"no JSON envelope found in {path}")


def _regular_nonempty(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and path.stat().st_size > 0


def validate_record(
    record: dict[str, Any], item: dict[str, Any], attempt_root: Path
) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    missing, unknown = RECORD_FIELDS - set(record), set(record) - RECORD_FIELDS
    require(not missing, f"record missing fields: {', '.join(sorted(missing))}")
    require(not unknown, f"record has unknown fields: {', '.join(sorted(unknown))}")
    require(record.get("schema_version") == 1, "schema_version must be 1")
    require(record.get("target_id") == item["target_id"], "target_id mismatch")
    require(record.get("source") == "GHSA", "source must be GHSA")
    require(
        isinstance(record.get("repository"), str)
        and record["repository"].startswith("https://"),
        "repository must be an authoritative HTTPS URL",
    )
    for field in ("recorded_vulnerable_commit", "proposed_fixed_commit"):
        value = record.get(field)
        require(
            value is None or isinstance(value, str) and bool(SHA40.fullmatch(value)),
            f"{field} must be null or a 40-character SHA",
        )
    require(
        record.get("original_exclusion_reason") is None,
        "original_exclusion_reason must be null",
    )
    require(
        isinstance(record.get("rejected_candidates"), list),
        "rejected_candidates must be an array",
    )
    require(
        record.get("advisory_year_month") == item["advisory_year_month"],
        "year-month mismatch",
    )
    require(nonempty(record.get("audited_at")), "audited_at is required")
    require(record.get("current_status") in CURRENT_STATUSES, "invalid current_status")
    require(record.get("proof_level") in PROOF_LEVELS, "invalid proof_level")
    for field in ("reported_root_cause", "attacker_boundary", "reasoning"):
        require(nonempty(record.get(field)), f"{field} is required")
    require(
        isinstance(record.get("equivalent_paths_checked"), list)
        and bool(record.get("equivalent_paths_checked")),
        "equivalent_paths_checked cannot be empty",
    )

    current = record.get("current_default")
    require(isinstance(current, dict), "current_default must be an object")
    if isinstance(current, dict):
        require(
            set(current) == {"ref", "commit", "resolved_at"},
            "current_default fields are invalid",
        )
        require(nonempty(current.get("ref")), "current_default.ref is required")
        require(
            isinstance(current.get("commit"), str)
            and bool(SHA40.fullmatch(current.get("commit", ""))),
            "current_default.commit is invalid",
        )
        require(
            nonempty(current.get("resolved_at")),
            "current_default.resolved_at is required",
        )

    branches = record.get("maintained_branches_examined")
    require(isinstance(branches, list), "maintained_branches_examined must be an array")
    if isinstance(branches, list):
        for index, branch in enumerate(branches):
            valid = isinstance(branch, dict) and {
                "ref",
                "commit",
                "maintenance_evidence",
                "status",
                "finding",
            } <= set(branch)
            require(valid, f"maintained_branches_examined[{index}] is invalid")
            if valid:
                require(
                    bool(SHA40.fullmatch(str(branch["commit"]))),
                    f"maintained_branches_examined[{index}].commit is invalid",
                )

    reproduction = record.get("reproduction")
    require(isinstance(reproduction, dict), "reproduction must be an object")
    if isinstance(reproduction, dict):
        for field in ("environment_preparation_commands", "commands", "observations"):
            require(
                isinstance(reproduction.get(field), list),
                f"reproduction.{field} must be an array",
            )
        for field in ("old_poc_result", "current_equivalent_path_result"):
            require(field in reproduction, f"reproduction.{field} is required")

    evidence = record.get("current_source_evidence")
    require(
        isinstance(evidence, list) and bool(evidence),
        "current_source_evidence cannot be empty",
    )
    bound_current = False
    if isinstance(evidence, list):
        for index, entry in enumerate(evidence):
            valid = isinstance(entry, dict) and {
                "url",
                "commit",
                "path",
                "lines",
                "finding",
            } <= set(entry)
            require(valid, f"current_source_evidence[{index}] is invalid")
            if valid:
                require(
                    str(entry["url"]).startswith("https://"),
                    f"evidence[{index}].url must be HTTPS",
                )
                require(
                    bool(SHA40.fullmatch(str(entry["commit"]))),
                    f"evidence[{index}].commit is invalid",
                )
                if isinstance(current, dict) and entry["commit"] == current.get(
                    "commit"
                ):
                    bound_current = True
        require(
            bound_current, "source evidence must bind to the current-default commit"
        )

    complete = record.get("complete_fix_outside_recorded_descendant_history")
    require(
        complete is None or isinstance(complete, bool),
        "complete_fix_outside_recorded_descendant_history must be boolean or null",
    )
    earliest = record.get("earliest_complete_current_fix")
    require(
        earliest is None or isinstance(earliest, dict),
        "earliest_complete_current_fix must be object or null",
    )
    if isinstance(earliest, dict):
        require(
            {"commit", "ref", "evidence"} <= set(earliest),
            "earliest_complete_current_fix fields are invalid",
        )
        require(
            bool(SHA40.fullmatch(str(earliest.get("commit", "")))),
            "earliest fix commit is invalid",
        )

    expected_artifact_root = str(
        (attempt_root / "artifacts").relative_to(attempt_root.parents[1])
    )
    require(
        record.get("artifact_root") == expected_artifact_root, "artifact_root mismatch"
    )
    required = (
        attempt_root / "artifacts/README.md",
        attempt_root / "artifacts/prepare-env.sh",
        attempt_root / "artifacts/run-poc.sh",
        attempt_root / "artifacts/observations.json",
        attempt_root / "report.md",
    )
    for path in required:
        require(
            _regular_nonempty(path),
            f"missing artifact: {path.relative_to(attempt_root)}",
        )
    if record.get("proof_level") == "executable":
        for relative in (
            "artifacts/logs/poc.stdout.log",
            "artifacts/logs/poc.stderr.log",
        ):
            require(
                (attempt_root / relative).is_file()
                and not (attempt_root / relative).is_symlink(),
                f"executable proof missing {relative}",
            )
    return errors


def preserve_dockerfile_inventory(target_root: Path, timestamp: str) -> None:
    inventory = target_root / "dockerfiles.json"
    files = []
    for path in sorted(target_root.rglob("*")):
        if (
            path == inventory
            or not path.is_file()
            or path.is_symlink()
            or "dockerfile" not in path.name.lower()
        ):
            continue
        files.append(
            {
                "path": str(path.relative_to(target_root)),
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
        )
    atomic_json(
        inventory,
        {
            "schema_version": 1,
            "updated_at": timestamp,
            "count": len(files),
            "files": files,
        },
    )
