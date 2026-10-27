from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .storage import atomic_json, sha256

SHA40 = re.compile(r"^[0-9a-f]{40}$")
LEGACY_CURRENT_STATUSES = {
    "still_present_current_default",
    "partially_fixed_but_same_vulnerability_reachable",
    "fixed_current_default",
    "fixed_default_but_present_on_maintained_release",
    "feature_removed_or_security_boundary_eliminated",
    "different_issue_only",
    "indeterminate",
}
CURRENT_STATUSES = LEGACY_CURRENT_STATUSES | {"risk_downgraded_current_default"}
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
RISK_DOWNGRADED = {"risk_downgraded_current_default"}
LEGACY_RECORD_FIELDS = {
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
RISK_FIELDS = {
    "reported_severity",
    "reported_impact",
    "current_severity",
    "current_impact",
    "impact_equivalence",
    "attacker_prerequisite_change",
    "risk_change",
    "risk_comparison",
}
RECORD_FIELDS = LEGACY_RECORD_FIELDS | RISK_FIELDS
SEVERITIES = {"critical", "high", "moderate", "low", "none", "unknown"}
SEVERITY_RANK = {"none": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}
IMPACT_EQUIVALENCE = {
    "same_or_greater",
    "reduced",
    "not_reached",
    "different_issue",
    "unproven",
}
PREREQUISITE_CHANGES = {"unchanged", "stricter", "looser", "different", "unproven"}
RISK_CHANGES = {
    "unchanged_or_higher",
    "downgraded",
    "not_reachable",
    "different_issue",
    "unproven",
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

    schema_version = record.get("schema_version")
    expected_fields = LEGACY_RECORD_FIELDS if schema_version == 1 else RECORD_FIELDS
    missing, unknown = expected_fields - set(record), set(record) - expected_fields
    require(not missing, f"record missing fields: {', '.join(sorted(missing))}")
    require(not unknown, f"record has unknown fields: {', '.join(sorted(unknown))}")
    require(schema_version in {1, 2}, "schema_version must be 1 or 2")
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
    allowed_statuses = LEGACY_CURRENT_STATUSES if schema_version == 1 else CURRENT_STATUSES
    require(record.get("current_status") in allowed_statuses, "invalid current_status")
    require(record.get("proof_level") in PROOF_LEVELS, "invalid proof_level")
    for field in ("reported_root_cause", "attacker_boundary", "reasoning"):
        require(nonempty(record.get(field)), f"{field} is required")
    if schema_version == 2:
        reported_severity = record.get("reported_severity")
        current_severity = record.get("current_severity")
        impact_equivalence = record.get("impact_equivalence")
        prerequisite_change = record.get("attacker_prerequisite_change")
        risk_change = record.get("risk_change")
        status = record.get("current_status")
        require(
            reported_severity == item.get("severity"),
            "reported_severity must match the immutable input",
        )
        require(reported_severity in SEVERITIES - {"none", "unknown"}, "invalid reported_severity")
        require(current_severity in SEVERITIES, "invalid current_severity")
        require(nonempty(record.get("reported_impact")), "reported_impact is required")
        require(nonempty(record.get("current_impact")), "current_impact is required")
        require(impact_equivalence in IMPACT_EQUIVALENCE, "invalid impact_equivalence")
        require(prerequisite_change in PREREQUISITE_CHANGES, "invalid attacker_prerequisite_change")
        require(risk_change in RISK_CHANGES, "invalid risk_change")
        require(nonempty(record.get("risk_comparison")), "risk_comparison is required")
        if status in STILL_PRESENT or status == "fixed_default_but_present_on_maintained_release":
            require(
                impact_equivalence == "same_or_greater",
                "reachable status requires the reported impact or greater",
            )
            require(
                prerequisite_change in {"unchanged", "looser"},
                "reachable status cannot require stricter attacker prerequisites",
            )
            require(
                risk_change == "unchanged_or_higher",
                "reachable status requires unchanged_or_higher risk",
            )
            if reported_severity in SEVERITY_RANK and current_severity in SEVERITY_RANK:
                require(
                    SEVERITY_RANK[current_severity] >= SEVERITY_RANK[reported_severity],
                    "reachable status cannot lower current_severity",
                )
        elif status == "risk_downgraded_current_default":
            require(risk_change == "downgraded", "downgraded status requires downgraded risk")
            require(
                impact_equivalence == "reduced"
                or prerequisite_change in {"stricter", "different"},
                "downgraded status requires reduced impact or stricter prerequisites",
            )
            if reported_severity in SEVERITY_RANK and current_severity in SEVERITY_RANK:
                require(
                    SEVERITY_RANK[current_severity] < SEVERITY_RANK[reported_severity],
                    "downgraded status requires a lower current_severity",
                )
        elif status in {"fixed_current_default", "feature_removed_or_security_boundary_eliminated"}:
            require(risk_change == "not_reachable", "fixed status requires not_reachable risk")
            require(impact_equivalence == "not_reached", "fixed status requires not_reached impact")
            require(current_severity == "none", "fixed status requires current_severity none")
        elif status == "different_issue_only":
            require(risk_change == "different_issue", "different issue status requires different_issue risk")
            require(impact_equivalence == "different_issue", "different issue status requires different_issue impact")
            require(current_severity == "none", "different issue status requires current_severity none")
        elif status == "indeterminate":
            require(risk_change == "unproven", "indeterminate status requires unproven risk")
            require(current_severity == "unknown", "indeterminate status requires current_severity unknown")
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
