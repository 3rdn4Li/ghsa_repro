from __future__ import annotations

from pathlib import Path
from typing import Any

from .pipeline import AuditPipeline, load_run, summarize
from .storage import atomic_json, utcnow


def _write_state(
    state_file: Path,
    run_dirs: list[Path],
    started_at: str,
    status: str,
    runs: list[dict[str, Any]],
    current_run: Path | None,
) -> dict[str, Any]:
    state = {
        "schema_version": 1,
        "status": status,
        "started_at": started_at,
        "updated_at": utcnow(),
        "run_dirs": [str(path) for path in run_dirs],
        "current_run": str(current_run) if current_run else None,
        "runs": runs,
    }
    atomic_json(state_file, state)
    return state


def run_sequence(
    run_dirs: list[Path],
    state_file: Path,
    *,
    jobs: int | None = None,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Run one bounded pass per run, stopping until each run is fully complete."""
    resolved = [path.resolve() for path in run_dirs]
    if not resolved:
        raise ValueError("run sequence requires at least one run directory")
    if len(set(resolved)) != len(resolved):
        raise ValueError("run sequence contains duplicate run directories")
    state_file = state_file.resolve()
    started_at = utcnow()
    run_states: list[dict[str, Any]] = []
    _write_state(state_file, resolved, started_at, "running", run_states, resolved[0])

    for root in resolved:
        paths, config, manifest = load_run(root)
        before = summarize(paths, config)
        entry: dict[str, Any] = {
            "run_dir": str(root),
            "targets": len(manifest),
            "completed_before": before["completed"],
        }
        if before["remaining"] == 0:
            entry.update({"status": "already_complete", "completed": before["completed"], "remaining": 0})
            run_states.append(entry)
            _write_state(state_file, resolved, started_at, "running", run_states, root)
            continue

        pipeline = AuditPipeline(paths, config, manifest)
        result = pipeline.run(
            jobs=jobs or config.codex.default_jobs,
            timeout_seconds=timeout_seconds or config.codex.timeout_seconds,
        )
        after = result["summary"]
        entry.update(
            {
                "status": "complete" if after["remaining"] == 0 else "incomplete",
                "completed": after["completed"],
                "remaining": after["remaining"],
                "failures": after["failures"],
                "finished_at": result["finished_at"],
            }
        )
        run_states.append(entry)
        if after["remaining"]:
            return _write_state(
                state_file,
                resolved,
                started_at,
                "stopped_incomplete",
                run_states,
                root,
            )
        _write_state(state_file, resolved, started_at, "running", run_states, root)

    state = _write_state(
        state_file, resolved, started_at, "complete", run_states, None
    )
    state["finished_at"] = utcnow()
    atomic_json(state_file, state)
    return state
