from __future__ import annotations

import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .config import RunConfig, require_secret
from .pipeline import agent_environment, codex_command
from .proxy import handler


def _binary(value: str) -> str:
    candidate = (
        str(Path(value).expanduser().resolve()) if "/" in value else shutil.which(value)
    )
    if not candidate or not Path(candidate).is_file():
        raise RuntimeError(f"Codex binary was not found: {value}")
    return candidate


def check(config: RunConfig) -> dict[str, object]:
    require_secret(config)
    binary = _binary(config.codex.binary)
    version = subprocess.run(
        [binary, "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
    )
    help_result = subprocess.run(
        [binary, "exec", "--help"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
    )
    if version.returncode != 0 or help_result.returncode != 0:
        raise RuntimeError("Codex CLI self-check failed")
    for option in (
        "--output-schema",
        "--output-last-message",
        "--dangerously-bypass-approvals-and-sandbox",
    ):
        if option not in help_result.stdout:
            raise RuntimeError(f"Codex CLI lacks required option: {option}")

    provider = config.provider
    status = None
    endpoint_response_object = None
    if provider.auth == "api_key":
        assert provider.base_url is not None
        assert provider.api_key_env is not None
        endpoint = provider.base_url.rstrip("/") + (
            "/chat/completions" if provider.wire_api == "chat" else "/responses"
        )
        if provider.wire_api == "chat":
            payload = {
                "model": provider.model,
                "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
                "max_tokens": 8,
                "stream": False,
            }
        else:
            payload = {
                "model": provider.model,
                "input": "Reply with exactly: OK",
                "max_output_tokens": 8,
                "stream": False,
            }
        request = Request(
            endpoint,
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {os.environ[provider.api_key_env]}",
                "Content-Type": "application/json",
                "User-Agent": "ghsa-repro/0.1",
            },
            method="POST",
        )
        context = None
        if endpoint.startswith("https://") and not provider.tls_verify:
            context = ssl._create_unverified_context()
        try:
            with urlopen(request, timeout=60, context=context) as response:
                result = json.load(response)
                status = response.status
        except HTTPError as error:
            raise RuntimeError(f"model endpoint returned HTTP {error.code}") from error
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"model endpoint check failed: {type(error).__name__}"
            ) from error
        if not isinstance(result, dict):
            raise RuntimeError("model endpoint returned a non-object response")
        endpoint_response_object = True
    else:
        login = subprocess.run(
            [binary, "login", "status"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
        if login.returncode != 0 or "Logged in using ChatGPT" not in login.stdout:
            raise RuntimeError("Codex is not logged in using ChatGPT")

    proxy = None
    codex_base_url = provider.base_url
    if provider.auth == "api_key" and not provider.tls_verify:
        assert provider.base_url is not None
        assert provider.api_key_env is not None
        from http.server import ThreadingHTTPServer

        proxy = ThreadingHTTPServer(
            ("127.0.0.1", 0), handler(provider.base_url, provider.api_key_env, False)
        )
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        codex_base_url = f"http://127.0.0.1:{proxy.server_port}"
    try:
        with tempfile.TemporaryDirectory(
            prefix=".ghsa-repro-doctor-", dir=Path.cwd()
        ) as temporary:
            root = Path(temporary)
            schema = root / "schema.json"
            output = root / "output.json"
            schema.write_text(
                json.dumps(
                    {
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["status"],
                        "properties": {"status": {"type": "string", "const": "ok"}},
                    }
                )
            )
            command = codex_command(
                config,
                binary,
                root,
                output,
                schema,
                'Return only this JSON object: {"status":"ok"}. Do not inspect files or run commands.',
                codex_base_url,
            )
            smoke = subprocess.run(
                command,
                cwd=root,
                env=agent_environment(config, root / "runtime"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
                check=False,
            )
            if smoke.returncode != 0:
                diagnostic = smoke.stderr[-1200:]
                if provider.api_key_env:
                    diagnostic = diagnostic.replace(
                        os.environ[provider.api_key_env], "[REDACTED]"
                    )
                diagnostic = re.sub(
                    r"(?i)(authorization|api[_-]?key|token)(\s*[:=]\s*)\S+",
                    r"\1\2[REDACTED]",
                    diagnostic,
                )
                raise RuntimeError(
                    f"structured Codex smoke test exited with {smoke.returncode}: {diagnostic.strip()}"
                )
            try:
                text = output.read_text(encoding="utf-8").strip()
                match = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
                structured = json.loads(match.group(1).strip() if match else text)
            except (OSError, json.JSONDecodeError) as error:
                raise RuntimeError(
                    "structured Codex smoke test produced no valid JSON"
                ) from error
            if structured != {"status": "ok"}:
                raise RuntimeError(
                    "structured Codex smoke test returned an unexpected object"
                )
    finally:
        if proxy is not None:
            proxy.shutdown()
            proxy.server_close()
    return {
        "config_valid": True,
        "auth": provider.auth,
        "credential_env_present": provider.auth == "api_key",
        "chatgpt_login_present": provider.auth == "chatgpt",
        "codex_binary": binary,
        "codex_version": version.stdout.strip(),
        "model": provider.model,
        "wire_api": provider.wire_api,
        "endpoint_http_status": status,
        "endpoint_response_object": endpoint_response_object,
        "structured_codex_smoke": True,
    }
