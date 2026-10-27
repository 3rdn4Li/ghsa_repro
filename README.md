# ghsa_repro

`ghsa_repro` is a self-contained, resumable pipeline for checking whether a published
GitHub Security Advisory's reported vulnerability is still reachable in the exact current
upstream source. It inventories immutable inputs, launches one isolated audit workspace per
GHSA, validates structured records and reproduction artifacts, and preserves every attempt.

The pipeline is year-independent. A 2022, 2023, or 2024 run differs only in its input JSONL
and run directory. The code never embeds a year, model credential, or campaign path.

## Responsible-use boundary

Run this only for authorized defensive research. Reproductions must target local disposable
containers or processes; never test public services. The Codex worker needs broad host access
to build heterogeneous upstream projects, so `run` requires an explicit risk acknowledgement.
Use a dedicated machine or VM with no production credentials or sensitive data.

API keys are read only from the environment variable named in the configuration. Their values
are not written to source, commands, configuration snapshots, state, or logs. Runtime outputs,
source checkouts, PoCs, model responses, and credentials are ignored by Git under `runs/`.

## Requirements

- Python 3.10 or newer
- Git and Docker for targets that require them
- A compatible Codex CLI with `codex exec`, custom model-provider configuration, structured
  output schemas, and the configured wire API
- Optional `GH_TOKEN` for reliable GitHub Advisory API access
- A model endpoint suitable and authorized for defensive vulnerability analysis

Install from a clone:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
npm install
ghsa-repro --help
```

There are no required third-party Python runtime packages.

## Canonical input format

JSONL is the authoritative input format: one JSON object per GHSA, no duplicate GHSA IDs.
Each record follows [`schemas/input-record.schema.json`](schemas/input-record.schema.json).

```json
{
  "schema_version": 1,
  "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
  "cve_id": "CVE-2023-0001",
  "published_at": "2023-06-15T12:00:00Z",
  "severity": "critical",
  "summary": "Advisory summary",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "source_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
  "packages": [
    {
      "ecosystem": "npm",
      "name": "example-package",
      "vulnerable_version_range": "< 2.0.0",
      "first_patched_version": "2.0.0"
    }
  ]
}
```

`cve_id`, `cvss_vector`, and `source_url` may be `null`; `packages` may be empty. The complete
advisory is fetched and frozen when each target is first staged, so package entries are hints,
not trusted repository or fix resolution.

Validate an input without creating a run:

```bash
ghsa-repro validate-input inputs/2023-critical.jsonl
```

### CSV compatibility

CSV is accepted for migration. The standard columns are:

```text
ghsa_id,cve_id,published_at,severity,summary,cvss_vector,source_url,packages_json
```

`packages_json` is a JSON array using the package shape above. Legacy campaign columns
`cve`, `published`, and `package` are also recognized. If a legacy CSV has no severity column,
the operator must state the selection assumption explicitly:

```bash
ghsa-repro validate-input old-2023-list.csv --assume-severity critical
```

## Collecting a year

`collect` reads GitHub's reviewed Global Security Advisories and excludes withdrawn entries.
Year always means the advisory's `published_at` year, not the year embedded in a CVE alias.

```bash
export GH_TOKEN="..."  # optional for small runs, recommended for rate limits
ghsa-repro collect \
  --year 2023 \
  --severity critical \
  --output inputs/2023-critical.jsonl
```

Repeat with `--year 2022` for 2022. For a custom selection policy—including CVE-number year—
produce JSONL matching the canonical schema and run `validate-input`; the audit stages remain
identical.

## Model configuration

Copy [`config.example.json`](config.example.json) and edit only non-secret settings. The checked-in
example matches a GLM-5.3 Chat Completions endpoint using `GLM_API_KEY_SECLAB`:

```bash
cp config.example.json config.local.json
export GLM_API_KEY_SECLAB="..."
ghsa-repro doctor --config config.local.json
```

`doctor` performs both a direct endpoint request and a schema-constrained Codex request. If
multiple Codex builds are installed, test the intended one with `--codex-binary /absolute/path`.

Important fields:

- `provider.model`: model sent to Codex
- `provider.base_url`: OpenAI-compatible endpoint
- `provider.base_url_env`: alternative to `base_url`; resolves the endpoint from an environment
  variable without writing it into the run configuration or attempt metadata
- `provider.api_key_env`: environment variable name, never the secret value
- `provider.wire_api`: `chat` or `responses`
- `provider.supports_output_schema`: set `false` for Chat Completions providers that reject
  Codex's `--output-schema`; local envelope and record validation still remains mandatory
- `provider.tls_verify`: set `false` only for a trusted private/self-signed endpoint; the pipeline
  creates a loopback TLS-terminating proxy and never logs the key
- `codex.binary`: executable name on `PATH` or an absolute path
- `codex.max_attempts_per_pass`: bounded retries for each target during one pass

The checked-in `package.json` pins Codex 0.80.0 because it supports the Chat Completions wire
API used by the GLM example. Newer Codex releases may reject `wire_api: chat`; Responses-based
providers may instead point `codex.binary` to a current compatible Codex and enable output-schema
support. Always run `doctor` after changing either the provider or Codex version.

The full configuration contract is [`schemas/run-config.schema.json`](schemas/run-config.schema.json).
Do not put credentials in this file.

[`config.daybreak.example.json`](config.daybreak.example.json) is the non-secret Daybreak Blue
profile. It reads both endpoint and key from `GPT_LITELLM_BASE_URL` and
`GPT_LITELLM_API_KEY`, enables `daybreak_blue`, and permits a 48-worker run. Public OpenAI
documentation does not currently specify this model alias, so use `doctor` and a one-target
validation with the intended account before starting parallel work.

## Starting a run

Initialization validates and freezes both input and effective non-secret configuration. It refuses
to overwrite a nonempty directory.

```bash
ghsa-repro init \
  --input inputs/2023-critical.jsonl \
  --config config.local.json \
  --run-dir runs/2023-critical-glm53
```

First validate one real target:

```bash
ghsa-repro run \
  --run-dir runs/2023-critical-glm53 \
  --jobs 1 \
  --target GHSA-xxxx-yyyy-zzzz \
  --acknowledge-local-security-risk
```

Inspect `records/<GHSA>.json`, its selected attempt, validation result, and reproduction artifacts.
After the single-target check succeeds, resume the full parallel run:

```bash
ghsa-repro run \
  --run-dir runs/2023-critical-glm53 \
  --jobs 8 \
  --timeout-seconds 7200 \
  --acknowledge-local-security-risk
```

Completed valid targets are checked and skipped. Failed or invalid targets receive new bounded
attempts on the next invocation. No restart discards a valid checkpoint.

## Explicit impact reassessment

Normal audits do not expose workers to earlier model conclusions. For a deliberate second-pass
review, `init-reassessment` creates a separate immutable run and freezes named prior record sets
as advisory-only evidence. This is useful when a first pass established a residual primitive but
did not prove that current impact and attacker prerequisites remain equivalent to the advisory.

```bash
ghsa-repro init-reassessment \
  --input inputs/reporting-queue.jsonl \
  --config config.local.json \
  --run-dir runs/reporting-impact-daybreak \
  --target GHSA-xxxx-yyyy-zzzz \
  --prior-record-set glm53=/absolute/path/to/glm-run/records \
  --prior-record-set daybreak=/absolute/path/to/daybreak-run/records
```

The new record contract separately captures reported/current impact, current severity, attacker
prerequisite changes, and overall risk change. A result cannot use a reachable status unless it
demonstrates the original impact or greater under unchanged or weaker attacker prerequisites.
Residual reachability with lower impact or stronger prerequisites must use
`risk_downgraded_current_default` and assign a lower current severity. Prior records are never
treated as proof; current upstream and reproduction evidence remain mandatory.

Every accepted record also produces a credential-scrubbed, non-PoC summary under
`published-records/<GHSA>.json`. Consumers such as a protected reporting dashboard can read this
directory incrementally without receiving complete reproduction commands, model logs, or private
canonical records.

## Monitoring and outputs

```bash
ghsa-repro monitor --run-dir runs/2023-critical-glm53
ghsa-repro summarize --run-dir runs/2023-critical-glm53
```

Each run is self-contained:

```text
runs/<name>/
  manifest.jsonl                 immutable normalized selection
  run-config.json                immutable non-secret effective config
  input-metadata.json            input/config hashes and provenance
  records/<GHSA>.json            canonical validated records
  published-records/<GHSA>.json  redacted incremental dashboard summary
  failures/<GHSA>.json           retryable failure evidence
  targets/<GHSA>/
    archived-inputs/             immutable advisory and normalized case
    attempts/NN/                 model output, logs, report, and reproduction artifacts
    selected-attempt.json
  summary.json
  REVIEW.md
  still-present.jsonl
  fixed-now.jsonl
  maintained-release-present.jsonl
  risk-downgraded.jsonl
  indeterminate.jsonl
  state.json
```

The canonical output contract is [`schemas/audit-record.schema.json`](schemas/audit-record.schema.json).
`proof_level: executable` is accepted only when required PoC logs exist and evidence is bound to the
exact current-default commit. Model success alone never creates a canonical record.

## Development

```bash
python -m unittest discover -s tests -v
```

Source code, schemas, the fixed English prompt, examples, and tests belong in Git. Never commit a
`runs/` directory or copy generated targets, source checkouts, responses, logs, credentials, or
runtime evidence into the repository.
