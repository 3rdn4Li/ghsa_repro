from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_-]*$")


@dataclass(frozen=True)
class ProviderConfig:
    id: str
    name: str
    model: str
    auth: str
    base_url: str | None
    base_url_env: str | None
    api_key_env: str | None
    wire_api: str
    supports_output_schema: bool
    tls_verify: bool
    request_max_retries: int = 10
    stream_max_retries: int = 20
    stream_idle_timeout_ms: int = 900_000


@dataclass(frozen=True)
class CodexConfig:
    binary: str
    max_jobs: int
    default_jobs: int
    timeout_seconds: int
    max_attempts_per_pass: int
    reasoning_effort: str | None
    cyber_access_program: str | None


@dataclass(frozen=True)
class RunConfig:
    provider: ProviderConfig
    codex: CodexConfig
    github_token_env: str

    def public_dict(self) -> dict[str, object]:
        """Return the complete non-secret effective configuration."""
        provider = vars(self.provider).copy()
        if self.provider.auth == "chatgpt":
            provider.pop("base_url")
            provider.pop("base_url_env")
            provider.pop("api_key_env")
        elif self.provider.base_url_env:
            provider.pop("base_url")
        else:
            provider.pop("base_url_env")
        return {
            "schema_version": 1,
            "provider": provider,
            "codex": vars(self.codex),
            "github_token_env": self.github_token_env,
        }


def _object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def _exact_keys(
    value: dict[str, object], required: set[str], optional: set[str], name: str
) -> None:
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        raise ValueError(f"{name} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{name} has unknown fields: {', '.join(sorted(unknown))}")


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _integer(value: object, name: str, minimum: int, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value


def load_config(path: Path) -> RunConfig:
    raw = _object(json.loads(path.read_text(encoding="utf-8")), "config")
    _exact_keys(
        raw,
        {"schema_version", "provider", "codex", "github_token_env"},
        set(),
        "config",
    )
    if raw["schema_version"] != 1:
        raise ValueError("config schema_version must be 1")

    provider = _object(raw["provider"], "provider")
    provider_required = {
        "id",
        "name",
        "model",
        "wire_api",
        "supports_output_schema",
        "tls_verify",
    }
    provider_optional = {
        "base_url",
        "base_url_env",
        "api_key_env",
        "auth",
        "request_max_retries",
        "stream_max_retries",
        "stream_idle_timeout_ms",
    }
    _exact_keys(provider, provider_required, provider_optional, "provider")
    provider_id = _string(provider["id"], "provider.id")
    if not PROVIDER_ID.fullmatch(provider_id):
        raise ValueError("provider.id must match ^[a-z][a-z0-9_-]*$")
    auth = provider.get("auth", "api_key")
    if auth not in {"api_key", "chatgpt"}:
        raise ValueError("provider.auth must be api_key or chatgpt")
    base_url_env_value = provider.get("base_url_env")
    base_url_value = provider.get("base_url")
    api_key_env_value = provider.get("api_key_env")
    base_url_env = None
    base_url = None
    api_key_env = None
    if auth == "chatgpt":
        if provider_id != "openai":
            raise ValueError("provider.auth chatgpt requires provider.id openai")
        if any((base_url_env_value, base_url_value, api_key_env_value)):
            raise ValueError(
                "provider.auth chatgpt does not accept base_url, base_url_env, or api_key_env"
            )
    else:
        if bool(base_url_env_value) == bool(base_url_value):
            raise ValueError("provider requires exactly one of base_url or base_url_env")
        if base_url_env_value:
            base_url_env = _string(base_url_env_value, "provider.base_url_env")
            if not ENV_NAME.fullmatch(base_url_env):
                raise ValueError(
                    "provider.base_url_env is not a valid environment variable name"
                )
            base_url = _string(os.environ.get(base_url_env), base_url_env).rstrip("/")
        else:
            base_url = _string(base_url_value, "provider.base_url").rstrip("/")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "provider.base_url must be an HTTP(S) origin or path without query/fragment"
            )
        api_key_env = _string(api_key_env_value, "provider.api_key_env")
        if not ENV_NAME.fullmatch(api_key_env):
            raise ValueError(
                "provider.api_key_env is not a valid environment variable name"
            )
    wire_api = _string(provider["wire_api"], "provider.wire_api")
    if wire_api not in {"chat", "responses"}:
        raise ValueError("provider.wire_api must be chat or responses")
    if not isinstance(provider["tls_verify"], bool):
        raise ValueError("provider.tls_verify must be a boolean")
    if not isinstance(provider["supports_output_schema"], bool):
        raise ValueError("provider.supports_output_schema must be a boolean")
    provider_config = ProviderConfig(
        id=provider_id,
        name=_string(provider["name"], "provider.name"),
        model=_string(provider["model"], "provider.model"),
        auth=auth,
        base_url=base_url,
        base_url_env=base_url_env,
        api_key_env=api_key_env,
        wire_api=wire_api,
        supports_output_schema=provider["supports_output_schema"],
        tls_verify=provider["tls_verify"],
        request_max_retries=_integer(
            provider.get("request_max_retries", 10), "request_max_retries", 0
        ),
        stream_max_retries=_integer(
            provider.get("stream_max_retries", 20), "stream_max_retries", 0
        ),
        stream_idle_timeout_ms=_integer(
            provider.get("stream_idle_timeout_ms", 900_000),
            "stream_idle_timeout_ms",
            1_000,
        ),
    )

    codex = _object(raw["codex"], "codex")
    codex_fields = {
        "binary",
        "max_jobs",
        "default_jobs",
        "timeout_seconds",
        "max_attempts_per_pass",
        "reasoning_effort",
        "cyber_access_program",
    }
    _exact_keys(codex, codex_fields, set(), "codex")
    effort = codex["reasoning_effort"]
    if effort not in {None, "low", "medium", "high", "xhigh"}:
        raise ValueError(
            "codex.reasoning_effort must be null, low, medium, high, or xhigh"
        )
    cyber = codex["cyber_access_program"]
    if cyber is not None:
        cyber = _string(cyber, "codex.cyber_access_program")
    max_jobs = _integer(codex["max_jobs"], "codex.max_jobs", 1)
    default_jobs = _integer(codex["default_jobs"], "codex.default_jobs", 1)
    if default_jobs > max_jobs:
        raise ValueError("codex.default_jobs cannot exceed codex.max_jobs")
    codex_config = CodexConfig(
        binary=_string(codex["binary"], "codex.binary"),
        max_jobs=max_jobs,
        default_jobs=default_jobs,
        timeout_seconds=_integer(codex["timeout_seconds"], "codex.timeout_seconds", 60),
        max_attempts_per_pass=_integer(
            codex["max_attempts_per_pass"], "codex.max_attempts_per_pass", 1, 10
        ),
        reasoning_effort=effort,
        cyber_access_program=cyber,
    )
    github_token_env = _string(raw["github_token_env"], "github_token_env")
    if not ENV_NAME.fullmatch(github_token_env):
        raise ValueError("github_token_env is not a valid environment variable name")
    return RunConfig(
        provider=provider_config, codex=codex_config, github_token_env=github_token_env
    )


def require_secret(config: RunConfig) -> None:
    if config.provider.auth == "api_key" and not os.environ.get(
        config.provider.api_key_env or ""
    ):
        raise RuntimeError(
            f"required environment variable is not set: {config.provider.api_key_env}"
        )
