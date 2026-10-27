from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    atomic_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode)


def immutable_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class RunPaths:
    root: Path

    @property
    def manifest(self) -> Path:
        return self.root / "manifest.jsonl"

    @property
    def config(self) -> Path:
        return self.root / "run-config.json"

    @property
    def metadata(self) -> Path:
        return self.root / "input-metadata.json"

    @property
    def records(self) -> Path:
        return self.root / "records"

    @property
    def failures(self) -> Path:
        return self.root / "failures"

    @property
    def targets(self) -> Path:
        return self.root / "targets"

    @property
    def runtime(self) -> Path:
        return self.root / "runtime"

    @property
    def prior_records(self) -> Path:
        return self.root / "prior-records"

    @property
    def lock(self) -> Path:
        return self.root / "run.lock"

    @property
    def state(self) -> Path:
        return self.root / "state.json"

    @property
    def active(self) -> Path:
        return self.root / "active.json"

    @property
    def summary(self) -> Path:
        return self.root / "summary.json"
