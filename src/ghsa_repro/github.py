from __future__ import annotations

import json
import os
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .input import validate_input_record

API = "https://api.github.com/advisories"


def fetch_advisory(
    ghsa_id: str, token_env: str = "GH_TOKEN"
) -> tuple[dict[str, object] | None, str | None]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ghsa-repro/0.1"}
    token = os.environ.get(token_env)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(
            Request(f"{API}/{ghsa_id}", headers=headers), timeout=60
        ) as response:
            value = json.load(response)
        if isinstance(value, dict) and value.get("ghsa_id") == ghsa_id:
            return value, None
        return None, "GitHub Advisory API returned an unexpected payload"
    except HTTPError as error:
        return None, f"GitHub Advisory API returned HTTP {error.code}"
    except (OSError, json.JSONDecodeError) as error:
        return None, f"{type(error).__name__}: {error}"


def _next_link(value: str | None) -> str | None:
    for part in (value or "").split(","):
        sections = [section.strip() for section in part.split(";")]
        if len(sections) > 1 and 'rel="next"' in sections[1:]:
            return sections[0].strip("<>")
    return None


def _package(value: object) -> dict[str, str | None] | None:
    if not isinstance(value, dict) or not isinstance(value.get("package"), dict):
        return None
    package = value["package"]
    ecosystem, name = package.get("ecosystem"), package.get("name")
    if (
        not isinstance(ecosystem, str)
        or not ecosystem
        or not isinstance(name, str)
        or not name
    ):
        return None
    patched = value.get("first_patched_version")
    if isinstance(patched, dict):
        patched = patched.get("identifier")
    return {
        "ecosystem": ecosystem,
        "name": name,
        "vulnerable_version_range": value.get("vulnerable_version_range") or None,
        "first_patched_version": patched
        if isinstance(patched, str) and patched
        else None,
    }


def _record(advisory: dict[str, object]) -> dict[str, object]:
    cvss = advisory.get("cvss") if isinstance(advisory.get("cvss"), dict) else {}
    packages = [
        item
        for item in (_package(value) for value in advisory.get("vulnerabilities", []))
        if item
    ]
    return validate_input_record(
        {
            "schema_version": 1,
            "ghsa_id": advisory.get("ghsa_id"),
            "cve_id": advisory.get("cve_id"),
            "published_at": advisory.get("published_at"),
            "severity": advisory.get("severity"),
            "summary": advisory.get("summary"),
            "cvss_vector": cvss.get("vector_string"),
            "source_url": advisory.get("html_url"),
            "packages": packages,
        }
    )


def collect_published_year(
    year: int,
    severity: str,
    *,
    token_env: str = "GH_TOKEN",
    opener=urlopen,
) -> list[dict[str, object]]:
    if year < 2000 or year > 9999:
        raise ValueError("year must be a four-digit year >= 2000")
    parameters = urlencode(
        {
            "type": "reviewed",
            "severity": severity,
            "published": f"{year}-01-01..{year}-12-31",
            "per_page": 100,
        }
    )
    url: str | None = API + "?" + parameters
    token = os.environ.get(token_env)
    records = []
    while url:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "ghsa-repro/0.1",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(url, headers=headers)
        try:
            with opener(request, timeout=60) as response:
                page = json.load(response)
                url = _next_link(response.headers.get("Link"))
        except HTTPError as error:
            raise RuntimeError(
                f"GitHub Advisory API returned HTTP {error.code}"
            ) from error
        if not isinstance(page, list):
            raise RuntimeError("GitHub Advisory API returned a non-array page")
        for advisory in page:
            if isinstance(advisory, dict) and not advisory.get("withdrawn_at"):
                records.append(_record(advisory))
    unique = {record["ghsa_id"]: record for record in records}
    return [unique[key] for key in sorted(unique)]
