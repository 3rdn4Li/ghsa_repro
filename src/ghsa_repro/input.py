from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

GHSA_ID = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SEVERITIES = {"low", "moderate", "high", "critical"}
INPUT_FIELDS = {
    "schema_version",
    "ghsa_id",
    "cve_id",
    "published_at",
    "severity",
    "summary",
    "cvss_vector",
    "source_url",
    "packages",
}


def _nullable_string(value: object, field: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string or null")
    return value.strip() or None


def _published(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("published_at must be a non-empty RFC 3339 timestamp")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("published_at must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("published_at must include a timezone")
    return text


def _packages(value: object) -> list[dict[str, str | None]]:
    if not isinstance(value, list):
        raise ValueError("packages must be an array")
    result = []
    allowed = {"ecosystem", "name", "vulnerable_version_range", "first_patched_version"}
    for index, package in enumerate(value):
        if (
            not isinstance(package, dict)
            or set(package) - allowed
            or not {"ecosystem", "name"} <= set(package)
        ):
            raise ValueError(f"packages[{index}] has missing or unknown fields")
        ecosystem = _nullable_string(
            package["ecosystem"], f"packages[{index}].ecosystem"
        )
        name = _nullable_string(package["name"], f"packages[{index}].name")
        if not ecosystem or not name:
            raise ValueError(f"packages[{index}] ecosystem and name cannot be empty")
        result.append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "vulnerable_version_range": _nullable_string(
                    package.get("vulnerable_version_range"),
                    f"packages[{index}].vulnerable_version_range",
                ),
                "first_patched_version": _nullable_string(
                    package.get("first_patched_version"),
                    f"packages[{index}].first_patched_version",
                ),
            }
        )
    return result


def validate_input_record(
    value: object, *, assumed_severity: str | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("input record must be a JSON object")
    unknown = set(value) - INPUT_FIELDS
    if unknown:
        raise ValueError(
            f"input record has unknown fields: {', '.join(sorted(unknown))}"
        )
    if value.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    ghsa_id = _nullable_string(value.get("ghsa_id"), "ghsa_id")
    if not ghsa_id or not GHSA_ID.fullmatch(ghsa_id):
        raise ValueError("ghsa_id must match GHSA-xxxx-xxxx-xxxx")
    cve_id = _nullable_string(value.get("cve_id"), "cve_id")
    if cve_id is not None and not CVE_ID.fullmatch(cve_id):
        raise ValueError("cve_id must match CVE-YYYY-NNNN or be null")
    severity = _nullable_string(value.get("severity"), "severity") or assumed_severity
    if severity not in SEVERITIES:
        raise ValueError("severity must be low, moderate, high, or critical")
    summary = _nullable_string(value.get("summary"), "summary")
    if not summary:
        raise ValueError("summary cannot be empty")
    source_url = _nullable_string(value.get("source_url"), "source_url")
    if source_url is not None and not source_url.startswith("https://"):
        raise ValueError("source_url must be an HTTPS URL or null")
    return {
        "schema_version": 1,
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "published_at": _published(value.get("published_at")),
        "severity": severity,
        "summary": summary,
        "cvss_vector": _nullable_string(value.get("cvss_vector"), "cvss_vector"),
        "source_url": source_url,
        "packages": _packages(value.get("packages", [])),
    }


def _legacy_package(value: str | None) -> list[dict[str, str | None]]:
    if not value or not value.strip():
        return []
    text = value.strip()
    ecosystem, separator, name = text.partition(":")
    if not separator or not ecosystem or not name:
        return [
            {
                "ecosystem": "unknown",
                "name": text,
                "vulnerable_version_range": None,
                "first_patched_version": None,
            }
        ]
    return [
        {
            "ecosystem": ecosystem,
            "name": name,
            "vulnerable_version_range": None,
            "first_patched_version": None,
        }
    ]


def _csv_records(path: Path, assumed_severity: str | None) -> Iterable[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        required = {"ghsa_id", "summary"}
        if not reader.fieldnames or not required <= set(reader.fieldnames):
            raise ValueError("CSV requires at least ghsa_id and summary columns")
        for number, row in enumerate(reader, 2):
            packages: object = []
            if row.get("packages_json"):
                try:
                    packages = json.loads(row["packages_json"])
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"CSV line {number}: invalid packages_json"
                    ) from error
            elif "package" in row:
                packages = _legacy_package(row.get("package"))
            value = {
                "schema_version": 1,
                "ghsa_id": row.get("ghsa_id"),
                "cve_id": row.get("cve_id") or row.get("cve") or None,
                "published_at": row.get("published_at") or row.get("published"),
                "severity": row.get("severity") or assumed_severity,
                "summary": row.get("summary"),
                "cvss_vector": row.get("cvss_vector") or None,
                "source_url": row.get("source_url") or None,
                "packages": packages,
            }
            try:
                yield validate_input_record(value, assumed_severity=assumed_severity)
            except ValueError as error:
                raise ValueError(f"CSV line {number}: {error}") from error


def load_input(
    path: Path, *, assumed_severity: str | None = None
) -> list[dict[str, Any]]:
    if assumed_severity is not None and assumed_severity not in SEVERITIES:
        raise ValueError("assumed severity must be low, moderate, high, or critical")
    records = []
    if path.suffix.lower() == ".csv":
        records.extend(_csv_records(path, assumed_severity))
    else:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(
                    validate_input_record(
                        json.loads(line), assumed_severity=assumed_severity
                    )
                )
            except (json.JSONDecodeError, ValueError) as error:
                raise ValueError(f"JSONL line {number}: {error}") from error
    if not records:
        raise ValueError("input contains no advisory records")
    ids = [record["ghsa_id"] for record in records]
    duplicates = sorted({target for target in ids if ids.count(target) > 1})
    if duplicates:
        raise ValueError(f"duplicate GHSA IDs: {', '.join(duplicates)}")
    return sorted(records, key=lambda record: record["ghsa_id"])


def jsonl(records: Iterable[dict[str, Any]]) -> str:
    return "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    )
