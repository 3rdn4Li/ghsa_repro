from __future__ import annotations

import atexit
import fcntl
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.resources import files
from pathlib import Path
from typing import Any

from .config import RunConfig, load_config, require_secret
from .github import fetch_advisory
from .input import jsonl, load_input
from .records import (
    FIXED_NOW,
    RISK_DOWNGRADED,
    STILL_PRESENT,
    parse_envelope,
    preserve_dockerfile_inventory,
    validate_record,
)
from .storage import (
    RunPaths,
    atomic_json,
    atomic_text,
    immutable_text,
    read_object,
    sha256,
    utcnow,
)

PRIOR_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(
        r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{12,}"
    ),
)


def _sanitize_prior_value(value: object) -> tuple[object, int]:
    if isinstance(value, str):
        redactions = 0
        for pattern in PRIOR_SECRET_PATTERNS:
            value, count = pattern.subn(
                lambda match: (match.group(1) if match.lastindex else "")
                + "[REDACTED]",
                value,
            )
            redactions += count
        return value, redactions
    if isinstance(value, list):
        output, redactions = [], 0
        for item in value:
            clean, count = _sanitize_prior_value(item)
            output.append(clean)
            redactions += count
        return output, redactions
    if isinstance(value, dict):
        output, redactions = {}, 0
        for key, item in value.items():
            lowered = str(key).lower()
            secret_key = lowered in {
                "password",
                "token",
                "secret",
                "api_key",
                "apikey",
                "authorization",
                "cookie",
            } or lowered.endswith(("_password", "_token", "_secret", "_api_key"))
            if secret_key and item not in (None, "", False):
                output[key] = "[REDACTED]"
                redactions += 1
            else:
                clean, count = _sanitize_prior_value(item)
                output[key] = clean
                redactions += count
        return output, redactions
    return value, 0


def initialize_run(
    input_path: Path,
    config_path: Path,
    run_root: Path,
    *,
    assumed_severity: str | None = None,
    selected_targets: list[str] | None = None,
    prior_record_sets: dict[str, Path] | None = None,
    run_kind: str = "standard",
) -> dict[str, Any]:
    config = load_config(config_path)
    inputs = load_input(input_path, assumed_severity=assumed_severity)
    if selected_targets:
        requested = list(dict.fromkeys(selected_targets))
        by_id = {record["ghsa_id"]: record for record in inputs}
        unknown = sorted(set(requested) - set(by_id))
        if unknown:
            raise ValueError(f"selected targets are not in the input: {', '.join(unknown)}")
        inputs = [by_id[target] for target in requested]
    if run_kind not in {"standard", "impact_reassessment"}:
        raise ValueError("unsupported run kind")
    prior_record_sets = prior_record_sets or {}
    if run_kind == "impact_reassessment" and not prior_record_sets:
        raise ValueError("impact reassessment requires prior record sets")
    run_root = run_root.resolve()
    if run_root.exists() and any(run_root.iterdir()):
        raise FileExistsError(f"run directory is not empty: {run_root}")
    run_root.mkdir(parents=True, exist_ok=True)
    paths = RunPaths(run_root)
    selected_at = utcnow()
    manifest = []
    for record in inputs:
        published = record["published_at"]
        manifest.append(
            {
                "schema_version": 1,
                "snapshot_selected_at": selected_at,
                "target_id": record["ghsa_id"],
                "source": "GHSA",
                "cve_id": record["cve_id"],
                "published_at": published,
                "severity": record["severity"],
                "summary": record["summary"],
                "cvss_vector": record["cvss_vector"],
                "source_url": record["source_url"],
                "packages": record["packages"],
                "advisory_year_month": published[:7],
            }
        )
    immutable_text(paths.manifest, jsonl(manifest))
    immutable_text(
        paths.config, json.dumps(config.public_dict(), indent=2, sort_keys=True) + "\n"
    )
    envelope = (
        files("ghsa_repro.resources")
        .joinpath("agent-envelope.schema.json")
        .read_text(encoding="utf-8")
    )
    immutable_text(run_root / "agent-envelope.schema.json", envelope)
    for directory in (
        paths.records,
        paths.failures,
        paths.targets,
        paths.runtime,
        paths.prior_records,
    ):
        directory.mkdir(mode=0o700, exist_ok=True)
    paths.published_records.mkdir(mode=0o755, parents=True, exist_ok=True)
    prior_metadata = []
    target_ids = {item["target_id"] for item in manifest}
    for label, source in sorted(prior_record_sets.items()):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", label):
            raise ValueError(f"invalid prior record label: {label}")
        source = source.resolve()
        if not source.is_dir():
            raise ValueError(f"prior record directory does not exist: {source}")
        copied = 0
        redactions = 0
        destination = paths.prior_records / label
        destination.mkdir(mode=0o700, exist_ok=False)
        for target_id in sorted(target_ids):
            prior = source / f"{target_id}.json"
            if not prior.is_file() or prior.is_symlink():
                continue
            value = read_object(prior)
            if value.get("target_id") != target_id:
                raise ValueError(f"prior record target mismatch: {prior}")
            clean, count = _sanitize_prior_value(value)
            immutable_text(
                destination / prior.name,
                json.dumps(clean, indent=2, sort_keys=True) + "\n",
            )
            copied += 1
            redactions += count
        prior_metadata.append(
            {
                "label": label,
                "source_directory": str(source),
                "copied_records": copied,
                "redactions": redactions,
            }
        )
    if run_kind == "impact_reassessment":
        missing_prior = [
            target_id
            for target_id in sorted(target_ids)
            if not any((paths.prior_records / label / f"{target_id}.json").is_file() for label in prior_record_sets)
        ]
        if missing_prior:
            raise ValueError(
                "impact reassessment targets lack prior records: " + ", ".join(missing_prior)
            )
    immutable_text(
        paths.metadata,
        json.dumps(
            {
                "schema_version": 1,
                "created_at": selected_at,
                "run_kind": run_kind,
                "input_path": str(input_path.resolve()),
                "input_sha256": sha256(input_path),
                "config_path": str(config_path.resolve()),
                "config_sha256": sha256(config_path),
                "target_count": len(manifest),
                "prior_record_sets": prior_metadata,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    summary = summarize(paths, config)
    return {"run_root": str(run_root), "targets": len(manifest), "summary": summary}


def load_manifest(path: Path) -> list[dict[str, Any]]:
    items = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict) or not value.get("target_id"):
            raise ValueError(f"invalid manifest line {number}")
        items.append(value)
    if not items:
        raise ValueError("manifest is empty")
    if len({item["target_id"] for item in items}) != len(items):
        raise ValueError("manifest contains duplicate target IDs")
    return items


def load_run(run_root: Path) -> tuple[RunPaths, RunConfig, list[dict[str, Any]]]:
    paths = RunPaths(run_root.resolve())
    for path in (paths.manifest, paths.config, paths.metadata):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"run is missing immutable input: {path}")
    return paths, load_config(paths.config), load_manifest(paths.manifest)


def _package_hints(item: dict[str, Any]) -> str:
    return json.dumps(
        item.get("packages") or [], ensure_ascii=False, separators=(",", ":")
    )


def render_prompt(
    item: dict[str, Any], attempt: int, prior_labels: list[str] | None = None
) -> str:
    template = (
        files("ghsa_repro.resources")
        .joinpath("audit_prompt.md")
        .read_text(encoding="utf-8")
    )
    attempt_dir = f"attempts/{attempt:02d}"
    values = {
        "TARGET_ID": item["target_id"],
        "CVE_ID": item.get("cve_id") or "none",
        "PUBLISHED_AT": item.get("published_at") or "unknown",
        "SEVERITY": item.get("severity") or "unknown",
        "PACKAGES": _package_hints(item),
        "SUMMARY": item.get("summary") or "unknown",
        "CVSS_VECTOR": item.get("cvss_vector") or "unknown",
        "ADVISORY_YEAR_MONTH": item["advisory_year_month"],
        "ATTEMPT_DIR": attempt_dir,
        "RUNTIME_DIR": f"{attempt_dir}/runtime-tmp",
        "PRIOR_AUDIT_CONTEXT": (
            "This explicit impact-reassessment run includes prior model records at "
            "`archived-inputs/prior-audits/`: "
            + ", ".join(f"`{label}.json`" for label in sorted(prior_labels or []))
            + ". Treat them only as advisory leads. Independently verify every claim against "
            "current upstream and reproduction evidence; do not copy their verdict or severity."
            if prior_labels
            else "No prior model record is supplied for this standard audit."
        ),
    }
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", str(value))
    if re.search(r"{{[A-Z0-9_]+}}", template):
        raise RuntimeError("unresolved prompt template variable")
    return template


def _stage_target(paths: RunPaths, config: RunConfig, item: dict[str, Any]) -> Path:
    target_root = paths.targets / item["target_id"]
    bundle = target_root / "archived-inputs" / "bundle"
    target_root.mkdir(parents=True, exist_ok=True)
    advisory_path = bundle / "advisory.json"
    if not advisory_path.exists():
        advisory, error = fetch_advisory(item["target_id"], config.github_token_env)
        if advisory is None:
            advisory = {
                "fetch_error": True,
                "ghsa_id": item["target_id"],
                "attempted_url": f"https://api.github.com/advisories/{item['target_id']}",
                "error": error,
            }
        immutable_text(
            advisory_path, json.dumps(advisory, indent=2, sort_keys=True) + "\n"
        )
    case_path = bundle / "case.json"
    if not case_path.exists():
        immutable_text(
            case_path,
            json.dumps(
                {
                    "schema_version": 1,
                    "target_id": item["target_id"],
                    "source": "GHSA",
                    "input": item,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
    task_path = bundle / "public" / "task.md"
    if not task_path.exists():
        immutable_text(
            task_path,
            "# GHSA current-upstream audit input\n\n"
            f"- GHSA: `{item['target_id']}`\n"
            f"- CVE: `{item.get('cve_id') or 'none'}`\n"
            f"- Published: `{item.get('published_at')}`\n"
            f"- Severity: `{item.get('severity')}`\n"
            f"- Package hints: `{_package_hints(item)}`\n\n"
            f"## Summary\n\n{item.get('summary')}\n\n"
            "The full public advisory captured by the orchestrator is in `advisory.json`. "
            "Repository and commit resolution are audit work, not trusted input.\n",
        )
    prior_paths = []
    for source in sorted(paths.prior_records.glob(f"*/{item['target_id']}.json")):
        label = source.parent.name
        destination = target_root / "archived-inputs" / "prior-audits" / f"{label}.json"
        if not destination.exists():
            immutable_text(destination, source.read_text(encoding="utf-8"))
        prior_paths.append(destination)
    inventory_path = target_root / "archived-inputs" / "inventory.json"
    if not inventory_path.exists():
        values = []
        for path in (advisory_path, case_path, task_path, *prior_paths):
            values.append(
                {
                    "archived_path": str(path.relative_to(target_root)),
                    "sha256": sha256(path),
                    "size": path.stat().st_size,
                }
            )
        immutable_text(
            inventory_path, json.dumps(values, indent=2, sort_keys=True) + "\n"
        )
    return target_root


def _resolve_binary(value: str) -> str:
    if "/" in value:
        candidate = Path(value).expanduser().resolve()
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise RuntimeError(f"Codex binary is not executable: {candidate}")
        return str(candidate)
    resolved = shutil.which(value)
    if not resolved:
        raise RuntimeError(f"Codex binary is not on PATH: {value}")
    return resolved


def _publish_record(paths: RunPaths, record: dict[str, Any]) -> None:
    fields = (
        "schema_version",
        "target_id",
        "source",
        "repository",
        "audited_at",
        "current_default",
        "reported_root_cause",
        "attacker_boundary",
        "reported_severity",
        "reported_impact",
        "current_severity",
        "current_impact",
        "impact_equivalence",
        "attacker_prerequisite_change",
        "risk_change",
        "risk_comparison",
        "current_status",
        "proof_level",
        "equivalent_paths_checked",
        "reasoning",
    )
    compact = {field: record.get(field) for field in fields}
    clean, redactions = _sanitize_prior_value(compact)
    if isinstance(clean, dict):
        clean["publication_redactions"] = redactions
    paths.published_records.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_json(
        paths.published_records / f"{record['target_id']}.json", clean, mode=0o644
    )


def codex_command(
    config: RunConfig,
    binary: str,
    target_root: Path,
    envelope: Path,
    schema: Path,
    prompt: str,
    base_url: str,
) -> list[str]:
    provider = config.provider
    command = [
        binary,
        "exec",
        "-C",
        str(target_root),
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        "--model",
        provider.model,
        "-c",
        f"model_provider={json.dumps(provider.id)}",
        "-c",
        f"model_providers.{provider.id}.name={json.dumps(provider.name)}",
        "-c",
        f"model_providers.{provider.id}.base_url={json.dumps(base_url)}",
        "-c",
        f"model_providers.{provider.id}.env_key={json.dumps(provider.api_key_env)}",
        "-c",
        f"model_providers.{provider.id}.wire_api={json.dumps(provider.wire_api)}",
        "-c",
        f"model_providers.{provider.id}.requires_openai_auth=false",
        "-c",
        f"model_providers.{provider.id}.supports_websockets=false",
        "-c",
        f"model_providers.{provider.id}.request_max_retries={provider.request_max_retries}",
        "-c",
        f"model_providers.{provider.id}.stream_max_retries={provider.stream_max_retries}",
        "-c",
        f"model_providers.{provider.id}.stream_idle_timeout_ms={provider.stream_idle_timeout_ms}",
    ]
    if config.codex.reasoning_effort:
        command.extend(
            [
                "-c",
                f"model_reasoning_effort={json.dumps(config.codex.reasoning_effort)}",
            ]
        )
    if config.codex.cyber_access_program:
        command.extend(["--cyber-access-program", config.codex.cyber_access_program])
    if provider.supports_output_schema:
        command.extend(["--output-schema", str(schema)])
    command.extend(["--output-last-message", str(envelope), prompt])
    return command


def agent_environment(config: RunConfig, runtime_root: Path) -> dict[str, str]:
    runtime_dirs = {
        "HOME": runtime_root / "home",
        "TMPDIR": runtime_root / "tmp",
        "TMP": runtime_root / "tmp",
        "TEMP": runtime_root / "tmp",
        "XDG_CACHE_HOME": runtime_root / "xdg-cache",
        "XDG_CONFIG_HOME": runtime_root / "xdg-config",
        "XDG_DATA_HOME": runtime_root / "xdg-data",
        "XDG_RUNTIME_DIR": runtime_root / "xdg-runtime",
        "PIP_CACHE_DIR": runtime_root / "pip-cache",
        "UV_CACHE_DIR": runtime_root / "uv-cache",
        "npm_config_cache": runtime_root / "npm-cache",
        "CARGO_HOME": runtime_root / "cargo-home",
        "RUSTUP_HOME": runtime_root / "rustup-home",
        "GOPATH": runtime_root / "go",
        "GOMODCACHE": runtime_root / "go/pkg/mod",
        "GRADLE_USER_HOME": runtime_root / "gradle-home",
        "CODEX_HOME": runtime_root / "codex-home",
    }
    for path in set(runtime_dirs.values()):
        path.mkdir(parents=True, exist_ok=True)
    runtime_dirs["XDG_RUNTIME_DIR"].chmod(0o700)
    environment = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL", "TERM", "SSL_CERT_FILE", "SSL_CERT_DIR")
        if os.environ.get(key)
    }
    environment.update({key: str(path) for key, path in runtime_dirs.items()})
    environment[config.provider.api_key_env] = os.environ[config.provider.api_key_env]
    return environment


def _terminate_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=15)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


class AuditPipeline:
    def __init__(
        self, paths: RunPaths, config: RunConfig, manifest: list[dict[str, Any]]
    ) -> None:
        self.paths = paths
        self.config = config
        self.manifest = manifest
        self.binary = _resolve_binary(config.codex.binary)
        self.write_lock = threading.Lock()
        self.active_lock = threading.Lock()
        self.active: dict[str, dict[str, Any]] = {}
        self.proxy: subprocess.Popen[str] | None = None

    def _write_active(self) -> None:
        atomic_json(
            self.paths.active,
            {
                "schema_version": 1,
                "updated_at": utcnow(),
                "workers": sorted(
                    self.active.values(), key=lambda value: value["target_id"]
                ),
            },
        )

    def stop_active(self) -> None:
        with self.active_lock:
            pids = [value["pid"] for value in self.active.values()]
        for pid in pids:
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def _start_proxy(self) -> str:
        if self.config.provider.tls_verify:
            return self.config.provider.base_url
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        proxy_environment = {
            key: os.environ[key]
            for key in (
                "PATH",
                "PYTHONPATH",
                "LANG",
                "LC_ALL",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
            )
            if os.environ.get(key)
        }
        proxy_environment[self.config.provider.api_key_env] = os.environ[
            self.config.provider.api_key_env
        ]
        self.proxy = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "ghsa_repro.proxy",
                "--upstream",
                self.config.provider.base_url,
                "--api-key-env",
                self.config.provider.api_key_env,
                "--port",
                str(port),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=proxy_environment,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proxy.poll() is not None:
                raise RuntimeError(
                    f"model endpoint proxy exited with {self.proxy.returncode}"
                )
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return f"http://127.0.0.1:{port}"
            except OSError:
                time.sleep(0.1)
        self._stop_proxy()
        raise RuntimeError("model endpoint proxy did not become ready")

    def _stop_proxy(self) -> None:
        if self.proxy is not None:
            _terminate_group(self.proxy)
            self.proxy = None

    def _execute(
        self,
        target_id: str,
        command: list[str],
        stdout_path: Path,
        stderr_path: Path,
        timeout_seconds: int,
        runtime_root: Path,
    ) -> tuple[int, str | None]:
        environment = agent_environment(self.config, runtime_root)
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            stdout_path.open("w", encoding="utf-8") as stdout,
            stderr_path.open("w", encoding="utf-8") as stderr,
        ):
            process = subprocess.Popen(
                command,
                cwd=command[command.index("-C") + 1],
                stdout=stdout,
                stderr=stderr,
                text=True,
                start_new_session=True,
                env=environment,
            )
            with self.active_lock:
                self.active[target_id] = {
                    "target_id": target_id,
                    "pid": process.pid,
                    "started_at": utcnow(),
                }
                self._write_active()
            try:
                try:
                    return process.wait(timeout=timeout_seconds), None
                except subprocess.TimeoutExpired:
                    _terminate_group(process)
                    return (
                        process.returncode or 124,
                        f"timed out after {timeout_seconds}s",
                    )
            finally:
                with self.active_lock:
                    self.active.pop(target_id, None)
                    self._write_active()

    def _checkpoint_valid(self, item: dict[str, Any]) -> bool:
        target_id = item["target_id"]
        try:
            record = read_object(self.paths.records / f"{target_id}.json")
            selected = read_object(
                self.paths.targets / target_id / "selected-attempt.json"
            )
            attempt_root = self.paths.targets / target_id / str(selected["attempt_dir"])
            return not validate_record(record, item, attempt_root)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return False

    def _audit_one(
        self, item: dict[str, Any], timeout_seconds: int, base_url: str
    ) -> dict[str, Any]:
        target_id = item["target_id"]
        if self._checkpoint_valid(item):
            return {"target_id": target_id, "outcome": "checkpoint_reused"}
        target_root = _stage_target(self.paths, self.config, item)
        prior = [
            int(path.name)
            for path in (target_root / "attempts").glob("[0-9][0-9]")
            if path.is_dir() and path.name.isdigit()
        ]
        first_attempt = max(prior, default=0) + 1
        if first_attempt + self.config.codex.max_attempts_per_pass - 1 > 99:
            raise RuntimeError(f"attempt limit exhausted for {target_id}")
        pass_history = []
        for attempt in range(
            first_attempt, first_attempt + self.config.codex.max_attempts_per_pass
        ):
            attempt_root = target_root / "attempts" / f"{attempt:02d}"
            attempt_root.mkdir(parents=True, exist_ok=False)
            runtime_root = attempt_root / "runtime-tmp"
            envelope = attempt_root / "agent-envelope.json"
            stdout_path = attempt_root / "agent.stdout.log"
            stderr_path = attempt_root / "agent.stderr.log"
            prior_labels = [
                path.stem
                for path in sorted(
                    (target_root / "archived-inputs" / "prior-audits").glob("*.json")
                )
            ]
            prompt = render_prompt(item, attempt, prior_labels)
            command = codex_command(
                self.config,
                self.binary,
                target_root,
                envelope,
                self.paths.root / "agent-envelope.schema.json",
                prompt,
                base_url,
            )
            atomic_json(
                attempt_root / "agent-config.json",
                {
                    "schema_version": 1,
                    "model": self.config.provider.model,
                    "reasoning_effort": self.config.codex.reasoning_effort,
                    "cyber_access_program": self.config.codex.cyber_access_program,
                    "provider_id": self.config.provider.id,
                    "api_key_env": self.config.provider.api_key_env,
                    "base_url": None if self.config.provider.base_url_env else self.config.provider.base_url,
                    "base_url_env": self.config.provider.base_url_env,
                    "tls_verification": self.config.provider.tls_verify,
                    "runtime_root": str(runtime_root.relative_to(self.paths.root)),
                    "started_at": utcnow(),
                    "timeout_seconds": timeout_seconds,
                },
            )
            returncode, process_error = self._execute(
                target_id,
                command,
                stdout_path,
                stderr_path,
                timeout_seconds,
                runtime_root,
            )
            candidate = attempt_root / "record.json"
            errors = []
            record: dict[str, Any] | None = None
            if process_error:
                errors.append(process_error)
            if returncode != 0:
                errors.append(f"codex exited with {returncode}")
            try:
                output = parse_envelope(envelope)
                if set(output) != {"target_id", "status", "record_path"}:
                    errors.append("agent envelope fields are invalid")
                if output.get("target_id") != target_id:
                    errors.append("agent envelope target mismatch")
                if output.get("status") != "completed":
                    errors.append("agent envelope did not report completed")
                if output.get("record_path") != f"attempts/{attempt:02d}/record.json":
                    errors.append("agent envelope record path mismatch")
            except (OSError, ValueError, json.JSONDecodeError) as error:
                errors.append(f"invalid agent envelope: {error}")
            try:
                record = read_object(candidate)
                errors.extend(validate_record(record, item, attempt_root))
            except (OSError, ValueError, json.JSONDecodeError) as error:
                errors.append(f"invalid record.json: {error}")
            preserve_dockerfile_inventory(target_root, utcnow())
            attempt_result = {
                "attempt": attempt,
                "finished_at": utcnow(),
                "returncode": returncode,
                "errors": errors,
                "stdout": str(stdout_path.relative_to(self.paths.root)),
                "stderr": str(stderr_path.relative_to(self.paths.root)),
            }
            atomic_json(attempt_root / "validation.json", attempt_result)
            pass_history.append(attempt_result)
            if not errors and record is not None:
                canonical = self.paths.records / f"{target_id}.json"
                atomic_json(canonical, record)
                atomic_json(
                    target_root / "selected-attempt.json",
                    {
                        "selected_at": utcnow(),
                        "attempt": attempt,
                        "attempt_dir": str(attempt_root.relative_to(target_root)),
                        "record": str(canonical.relative_to(self.paths.root)),
                    },
                )
                _publish_record(self.paths, record)
                (self.paths.failures / f"{target_id}.json").unlink(missing_ok=True)
                with self.write_lock:
                    summarize(self.paths, self.config)
                return {
                    "target_id": target_id,
                    "outcome": "completed",
                    "status": record["current_status"],
                }
        atomic_json(
            self.paths.failures / f"{target_id}.json",
            {
                "schema_version": 1,
                "target_id": target_id,
                "failed_at": utcnow(),
                "attempts": pass_history,
                "retryable": True,
            },
        )
        with self.write_lock:
            summarize(self.paths, self.config)
        return {"target_id": target_id, "outcome": "failed"}

    def run(
        self,
        *,
        jobs: int,
        timeout_seconds: int,
        target_ids: list[str],
    ) -> dict[str, Any]:
        if jobs < 1 or jobs > self.config.codex.max_jobs:
            raise ValueError(f"jobs must be between 1 and {self.config.codex.max_jobs}")
        if timeout_seconds < 60:
            raise ValueError("timeout must be at least 60 seconds")
        require_secret(self.config)
        by_id = {item["target_id"]: item for item in self.manifest}
        if target_ids:
            unknown = sorted(set(target_ids) - set(by_id))
            if unknown:
                raise ValueError(
                    f"targets are not in the immutable manifest: {', '.join(unknown)}"
                )
            selected = [by_id[target] for target in dict.fromkeys(target_ids)]
        else:
            selected = self.manifest
        pending = [item for item in selected if not self._checkpoint_valid(item)]
        self.paths.lock.touch(mode=0o600, exist_ok=True)
        with self.paths.lock.open("r+", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError(
                    f"another orchestrator holds {self.paths.lock}"
                ) from error
            base_url = self._start_proxy()
            atexit.register(self._stop_proxy)
            started = utcnow()
            atomic_json(
                self.paths.state,
                {
                    "schema_version": 1,
                    "status": "running",
                    "jobs": jobs,
                    "selected": len(selected),
                    "pending_at_start": len(pending),
                    "started_at": started,
                    "model": self.config.provider.model,
                    "reasoning_effort": self.config.codex.reasoning_effort,
                    "provider_id": self.config.provider.id,
                },
            )
            results = []
            executor = ThreadPoolExecutor(
                max_workers=jobs, thread_name_prefix="ghsa-repro"
            )
            futures = {
                executor.submit(self._audit_one, item, timeout_seconds, base_url): item
                for item in pending
            }
            interrupted = False
            try:
                for future in as_completed(futures):
                    item = futures[future]
                    try:
                        result = future.result()
                    except Exception as error:  # noqa: BLE001 - isolate one target from the campaign
                        result = {
                            "target_id": item["target_id"],
                            "outcome": "orchestrator_error",
                            "error": f"{type(error).__name__}: {error}",
                        }
                        atomic_json(
                            self.paths.failures / f"{item['target_id']}.json",
                            {
                                "schema_version": 1,
                                "target_id": item["target_id"],
                                "failed_at": utcnow(),
                                "orchestrator_error": result["error"],
                                "retryable": True,
                            },
                        )
                    results.append(result)
                    print(json.dumps(result, sort_keys=True), flush=True)
            except KeyboardInterrupt:
                interrupted = True
                self.stop_active()
                for future in futures:
                    future.cancel()
                raise
            finally:
                executor.shutdown(wait=not interrupted, cancel_futures=True)
                self._stop_proxy()
                atexit.unregister(self._stop_proxy)
            summary = summarize(self.paths, self.config)
            final = {
                "schema_version": 1,
                "status": "completed_pass",
                "jobs": jobs,
                "selected": len(selected),
                "pending_at_start": len(pending),
                "timeout_seconds": timeout_seconds,
                "model": self.config.provider.model,
                "reasoning_effort": self.config.codex.reasoning_effort,
                "provider_id": self.config.provider.id,
                "started_at": started,
                "finished_at": utcnow(),
                "results": results,
                "summary": summary,
            }
            atomic_json(self.paths.state, final)
            return final


def _valid_records(
    paths: RunPaths, manifest: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    by_id = {item["target_id"]: item for item in manifest}
    records, invalid = [], 0
    for path in sorted(paths.records.glob("GHSA-*.json")):
        try:
            record = read_object(path)
            item = by_id[record["target_id"]]
            selected = read_object(
                paths.targets / record["target_id"] / "selected-attempt.json"
            )
            attempt_root = (
                paths.targets / record["target_id"] / str(selected["attempt_dir"])
            )
            if validate_record(record, item, attempt_root):
                invalid += 1
            else:
                records.append(record)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            invalid += 1
    return records, invalid


def summarize(paths: RunPaths, config: RunConfig) -> dict[str, Any]:
    manifest = load_manifest(paths.manifest)
    records, invalid = _valid_records(paths, manifest)
    failures = sorted(path.stem for path in paths.failures.glob("GHSA-*.json"))
    by_status = Counter(str(record.get("current_status")) for record in records)
    by_month = Counter(str(record.get("advisory_year_month")) for record in records)
    by_proof = Counter(str(record.get("proof_level")) for record in records)
    by_risk_change = Counter(
        str(record.get("risk_change", "legacy_unassessed")) for record in records
    )
    by_current_severity = Counter(
        str(record.get("current_severity", "legacy_unassessed")) for record in records
    )
    still = [
        record for record in records if record.get("current_status") in STILL_PRESENT
    ]
    fixed = [record for record in records if record.get("current_status") in FIXED_NOW]
    maintained = [
        record
        for record in records
        if record.get("current_status")
        == "fixed_default_but_present_on_maintained_release"
    ]
    indeterminate = [
        record for record in records if record.get("current_status") == "indeterminate"
    ]
    downgraded = [
        record for record in records if record.get("current_status") in RISK_DOWNGRADED
    ]
    outputs = {
        "still-present.jsonl": still,
        "fixed-now.jsonl": fixed,
        "maintained-release-present.jsonl": maintained,
        "indeterminate.jsonl": indeterminate,
        "risk-downgraded.jsonl": downgraded,
    }
    for name, values in outputs.items():
        atomic_text(paths.root / name, jsonl(values))
    summary = {
        "schema_version": 1,
        "updated_at": utcnow(),
        "snapshot_total": len(manifest),
        "completed": len(records),
        "remaining": len(manifest) - len(records),
        "failures": len(failures),
        "invalid_records": invalid,
        "counts": {
            "by_status": dict(sorted(by_status.items())),
            "by_year_month": dict(sorted(by_month.items())),
            "by_proof_level": dict(sorted(by_proof.items())),
            "by_risk_change": dict(sorted(by_risk_change.items())),
            "by_current_severity": dict(sorted(by_current_severity.items())),
            "still_vulnerable_now": len(still),
            "risk_downgraded_now": len(downgraded),
            "fixed_default_but_present_on_maintained_release": len(maintained),
            "fixed_now": len(fixed),
            "indeterminate": len(indeterminate),
        },
        "model": config.provider.model,
        "provider_id": config.provider.id,
        "reasoning_effort": config.codex.reasoning_effort,
    }
    atomic_json(paths.summary, summary)
    years = sorted({item["published_at"][:4] for item in manifest})
    review = [
        "# GHSA current-upstream audit",
        "",
        f"Updated: `{summary['updated_at']}`",
        "",
        f"Published-year scope: {', '.join(years)}",
        "",
        f"Immutable targets: {len(manifest)}; valid records: {len(records)}; failures: {len(failures)}.",
        "",
        "## Counts",
        "",
        "```json",
        json.dumps(summary["counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## Failed targets",
        "",
        ", ".join(failures) if failures else "None.",
        "",
    ]
    atomic_text(paths.root / "REVIEW.md", "\n".join(review))
    return summary


def monitor(paths: RunPaths) -> dict[str, Any]:
    state = read_object(paths.state) if paths.state.exists() else {}
    summary = read_object(paths.summary) if paths.summary.exists() else {}
    active_data = (
        read_object(paths.active) if paths.active.exists() else {"workers": []}
    )
    workers = []
    for worker in active_data.get("workers", []):
        try:
            os.kill(int(worker["pid"]), 0)
        except (OSError, KeyError, TypeError, ValueError):
            continue
        workers.append(worker)
    return {
        "state": state,
        "summary": summary,
        "active_worker_count": len(workers),
        "active_workers": workers,
    }
