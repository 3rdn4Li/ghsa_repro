Audit only `{{TARGET_ID}}` for the exact current-upstream presence of the reported vulnerability.

The immutable input snapshot records:

- GHSA: `{{TARGET_ID}}`
- CVE: `{{CVE_ID}}`
- Published: `{{PUBLISHED_AT}}`
- Severity: `{{SEVERITY}}`
- Package hints: `{{PACKAGES}}`
- CVSS vector: `{{CVSS_VECTOR}}`
- Year-month bucket: `{{ADVISORY_YEAR_MONTH}}`
- Summary: {{SUMMARY}}

Nothing is pre-resolved. The GitHub advisory captured by the orchestrator is at
`archived-inputs/bundle/advisory.json`; `case.json` and `public/task.md` restate the
input row. Treat all of `archived-inputs/` as immutable. If `advisory.json` records a
fetch error, retrieve the public advisory yourself and save it under
`{{ATTEMPT_DIR}}/artifacts/evidence/`, not under `archived-inputs/`.

{{PRIOR_AUDIT_CONTEXT}}

Discover the authoritative upstream repository from primary advisory or package
evidence. Never substitute a fork or unofficial mirror. Establish the proposed fixed
commit and best-supported recorded vulnerable commit when possible, using exact
40-character SHAs. Reconstruct the reported root cause, attacker boundary, and impact.

Risk-equivalence requirement:

- Separately state the advisory's reported impact and the strongest impact actually
  demonstrated on current upstream. An intermediate gadget, sink reachability, class
  instantiation, crash, or attacker-controlled primitive is not equivalent to the
  advisory's final RCE, authentication bypass, arbitrary write, disclosure, or other impact.
- Actively test materially equivalent paths that could still achieve the original impact.
  Make a reasonable evidence-driven effort to reach the original severity, but never infer,
  inflate, or manufacture impact that was not demonstrated.
- Compare attacker prerequisites. A new trusted-local action, pre-existing symlink,
  administrator-controlled configuration, victim-supplied object, non-default feature, or
  other stronger prerequisite is a risk downgrade unless the original boundary already
  required it.
- Use a reachable status only when current evidence establishes the reported impact or a
  greater impact under unchanged or weaker attacker prerequisites. If the same root cause
  or a residual primitive remains but impact is reduced or prerequisites are stronger, use
  `risk_downgraded_current_default` and assign the current severity independently.
- If equivalence cannot be established, use `indeterminate`; lack of proof is not proof of
  either a fix or unchanged critical severity.

Execution contract:

- Write every new output only below `{{ATTEMPT_DIR}}/` in the current target directory.
- Use `{{RUNTIME_DIR}}/` for every host-side checkout, build tree, package cache,
  temporary file, socket, and PoC scratch path. Preserve the temporary/cache environment
  supplied by the orchestrator.
- Do not modify anything outside this target directory. Do not modify pipeline code,
  another target, or `archived-inputs/`.
- Reproduction must be local and isolated. Never send attack traffic to a public service.
- Native builds are allowed. Retain all preparation and PoC commands as rerunnable scripts.
- Do not delete or overwrite Dockerfiles. Give every created Docker image/container a
  target-specific name or label. Never run global Docker cleanup.

Resolve the exact current default branch and actively maintained affected release
branches. Record each ref, exact commit, and UTC resolution time. Inspect the proposed
fix and materially relevant follow-ups. Check equivalent attacker-controlled paths, not
only the advisory example.

Prefer a source-faithful executable reproduction against the exact current commit. An
old PoC becoming clean does not prove a fix. Exact-input filtering, a guard on only one
path, optional mitigation, feature disablement, or an unrelated clean snapshot does not
establish a root-cause fix. Do not patch production source to force a result; additive
diagnostics are allowed. A failed build is not evidence of a fix.

Create this complete tree:

```text
{{ATTEMPT_DIR}}/
  record.json
  report.md
  artifacts/
    README.md
    prepare-env.sh
    run-poc.sh
    observations.json
    environment/
    poc/
    logs/
      prepare.stdout.log
      prepare.stderr.log
      poc.stdout.log
      poc.stderr.log
    evidence/
```

`artifacts/README.md` must document prerequisites, preparation, exact commands, expected
vulnerable/fixed behavior, actual behavior, exit-code interpretation, current commit, and
isolation assumptions. Both shell scripts must be noninteractive and rerunnable from the
target directory. Capture complete command output in `artifacts/logs/`. If executable
reproduction is impractical, say why and make the scripts perform the strongest safe
static checks without claiming executable proof.

Before finishing, record created Docker image IDs, digests, sizes, labels, and build
commands under `artifacts/evidence/`; stop and remove only resources created by this
attempt. Retained build definitions and logs must be sufficient to rebuild them.

Write `record.json` with exactly these semantic fields:

- `schema_version`: `2`
- `target_id`: `{{TARGET_ID}}`
- `source`: `GHSA`
- `repository`: authoritative upstream HTTPS URL
- `recorded_vulnerable_commit`: 40-character SHA or null
- `proposed_fixed_commit`: 40-character SHA or null
- `original_exclusion_reason`: null
- `rejected_candidates`: array
- `advisory_year_month`: `{{ADVISORY_YEAR_MONTH}}`
- `audited_at`: UTC timestamp
- `current_default`: object with `ref`, 40-character `commit`, and `resolved_at`
- `maintained_branches_examined`: array of objects with `ref`, `commit`,
  `maintenance_evidence`, `status`, and `finding`
- `reported_root_cause`: nonempty string
- `attacker_boundary`: nonempty string
- `reported_severity`: exactly `{{SEVERITY}}`
- `reported_impact`: nonempty description of the advisory's final security impact
- `current_severity`: one of `critical`, `high`, `moderate`, `low`, `none`, `unknown`
- `current_impact`: nonempty description of the strongest current impact actually supported
- `impact_equivalence`: one of `same_or_greater`, `reduced`, `not_reached`,
  `different_issue`, `unproven`
- `attacker_prerequisite_change`: one of `unchanged`, `stricter`, `looser`, `different`,
  `unproven`
- `risk_change`: one of `unchanged_or_higher`, `downgraded`, `not_reachable`,
  `different_issue`, `unproven`
- `risk_comparison`: concise evidence-based comparison of original and current risk
- `current_status`: one of `still_present_current_default`,
  `partially_fixed_but_same_vulnerability_reachable`, `fixed_current_default`,
  `fixed_default_but_present_on_maintained_release`,
  `feature_removed_or_security_boundary_eliminated`, `different_issue_only`,
  `risk_downgraded_current_default`, `indeterminate`
- `proof_level`: one of `executable`, `static_strong`, `static_partial`, `indeterminate`
- `equivalent_paths_checked`: nonempty array
- `reproduction`: object with array fields `environment_preparation_commands`, `commands`,
  and `observations`, plus `old_poc_result` and `current_equivalent_path_result`
- `current_source_evidence`: nonempty array of objects with `url`, `commit`, `path`,
  `lines`, and `finding`; at least one HTTPS primary-source URL must bind to the audited
  current-default commit
- `complete_fix_outside_recorded_descendant_history`: boolean or null
- `earliest_complete_current_fix`: object with `commit`, `ref`, and `evidence`, or null
- `artifact_root`: `{{ATTEMPT_DIR}}/artifacts`
- `reasoning`: concise nonempty explanation tied to the same root cause, boundary, and impact

Status consistency is mandatory: reachable statuses require `same_or_greater` impact,
unchanged/weaker prerequisites, `unchanged_or_higher` risk, and a current severity no lower
than the reported severity. `risk_downgraded_current_default` requires downgraded risk and a
lower current severity. Fixed/removed statuses require `not_reachable`, `not_reached`, and
severity `none`; indeterminate requires unproven risk and severity `unknown`.

Use `proof_level: executable` only when the exact current commit was built/run and the
claimed behavior was observed through the production entry path. Use `indeterminate`
when evidence cannot support another status.

After validating every file, return only:

```json
{"target_id":"{{TARGET_ID}}","status":"completed","record_path":"{{ATTEMPT_DIR}}/record.json"}
```
