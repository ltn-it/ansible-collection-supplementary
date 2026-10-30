# Lightning IT Ansible Collection Agent Guide (lit.*)

This file is the single source of truth for creating and evolving roles, Molecule scenarios,
and role documentation in `ansible-collection-*` repositories under the `lit.*` namespace.

Scope: role code, defaults, tasks, Molecule tests, role READMEs, CI, evidence, governance, release, and collection
packaging hygiene.

## 0. Compatibility Baseline

1. Content MUST be compatible with the `ansible-core` range declared in `meta/runtime.yml`.
2. Content MUST NOT require Ansible major versions newer than 2.x.
3. `meta/runtime.yml` is the source of truth for `requires_ansible`; do not hardcode a different baseline in code,
   docs, tests, or CI.
4. New changes SHOULD remain compatible with the declared minimum version unless explicitly told otherwise.
5. Prefer `ansible.builtin.*` modules; use external collections only when required and declared in `galaxy.yml`.

## 1. Mandatory Discovery Before Changes

Before writing or changing role code, you MUST inspect repository reality first:

1. `galaxy.yml` for namespace/name/license/tags/dependencies/build_ignore.
2. `meta/runtime.yml` for collection compatibility.
3. Lint config: `.ansible-lint`, `ansible-lint.yml`, `.yamllint`, `.pre-commit-config.yaml`.
4. Existing role patterns under `roles/` (tasks, defaults, assert entrypoints, naming).
5. Molecule and script behavior under `molecule/` and `scripts/devtools-molecule.sh`.

If generic guidance conflicts with repository behavior, you MUST prefer repository behavior.

## 1.1 Shared-Assets Managed Files (Mandatory)

1. This repository receives centrally managed baseline files rendered from `lightning-it/shared-assets-lit`.
2. Do not hand-edit these files in downstream repos unless you also update `shared-assets-lit` and run sync.
3. Automated shared-assets synchronization for this repository is allowlist-only. It may update exactly:
   1. the marked shared block in `.pre-commit-config.yaml`
   2. `scripts/wunder-container-run.sh`
   3. the digest-pinned validation-image custom manager in `renovate.json`
   4. `scripts/dispatch-transition-validation.py`
4. The sync MUST preserve every other Renovate setting and all repository-local workflows, scripts, documentation,
   tests, evidence schemas, and release-model metadata. Generic script/workflow `rsync --delete` and generic release
   model rendering MUST NOT run against this repository.
5. Other baseline material may be adopted from `shared-assets-lit` through an ordinary reviewed change, but it is
   repository-local after adoption and MUST NOT be overwritten by automated synchronization.
6. Repo-local exceptions MUST be explicit in the central sync workflow, documented here, and covered by regression
   tests in `shared-assets-lit`.
7. The role-quality governance block in this file is enforced by `scripts/validate-role-coverage.py` and recorded in
   `.lit/repository.yml`; a shared-assets sync MUST preserve it.
8. Until a fresh real Security release proves `humanActions=0`, this repository owns exactly
   `.github/workflows/copilot-review.yml`, `scripts/security-release-intake.py`,
   `.github/workflows/security-release-intake.yml`, `scripts/security-release-dispatch.py`,
   `.github/workflows/security-release-dispatch.yml`, and
   `tests/unit/test_security_release_request_dispatch.py`. Sync MUST preserve them byte-for-byte; after acceptance,
   their proven versions are canonicalized once in `shared-assets-lit`.

## 1.2 Local AI-Egress and Current-Revision Review Boundary (Mandatory)

1. Local Push-Ready commands are deterministic only. They MUST NOT invoke Codex, Copilot, or another external AI
   service and MUST record `local_ai_egress=prohibited` with zero local AI invocations.
2. Personal AI credentials, provider keys, and GitHub tokens MUST NOT be copied into repository automation,
   generated evidence, review workspaces, containers, or GitHub Actions.
3. The authoritative AI acceptance boundary is the protected `Current revision review` check on the exact live PR
   head. Local advisory evidence never substitutes for that protected check.
4. Pull requests authored by the exact Release App use only the MLX-90 §7.2 protected Exact-Revision Codex path,
   except for an exact, exhaustively verified ancestry-only `main` to `develop` backmerge. That one REP-60 case
   uses the deterministic evidence-bound zero-AI exception and MUST NOT dispatch Codex or Copilot. Protected
   `develop` to `main` promotions instead aggregate the exact native acceptance evidence of every ingress through
   the organization Required Workflow, without a second AI review of the cumulative diff. The repository-local
   promoter MUST publish the canonical `lit-protected-promotion:v2` binding at PR creation; missing or stale
   coverage fails closed. No other deterministic Release-App exception is permitted, and Release-App PRs MUST
   NOT claim or fall back to GitHub Copilot review.
   Supplementary retains its `main`-only `ansible-collection-release-prepare` environment for this promoter;
   `develop` and scheduled events may only relay to that protected-main workflow without receiving App credentials.
5. Lightning IT automation MAY automatically request a paid Copilot review only for the exact personal account
   `litroc`. External contributors must supply valid current-head evidence using their own entitlement; Lightning IT
   MUST NOT request or fund their AI usage.
6. The protected human Copilot request job MUST restrict its immutable predicate to `litroc` and MUST re-prove the
   live pull-request author as exactly `litroc` immediately before requesting review. A contributor-funded path may
   never return success from the Lightning IT-funded request job.
7. If GitHub exposes a completed Copilot review through GraphQL before the REST review collection converges, the
   controller MUST bind the exact GraphQL review node ID and re-prove that same ID and head through a bounded,
   read-only REST convergence wait before and after publishing the protected result. It MUST NOT request AI again.
8. Candidate-controlled Codex output is not a protected attestation. Until a separately governed, identity-bound
   personal-Codex evidence contract exists, it cannot satisfy `Current revision review`; the gate fails closed.
9. The original `pull_request_target` requester and event handoff execute from the exact protected default
   `develop` controller. Bind that execution ref/SHA independently of the authenticated PR base ref/SHA.
   A deferred-request `workflow_dispatch` consumer executes from the exact protected PR base revision
   (`develop` or `main`); a descendant controller is insufficient at its CAS and request effect fences.
   Attestations MUST retain both source roles without relabelling the original default source as the PR base,
   together with the actual head repository and head SHA.
10. The neutral result MUST bind the sorted live label set by SHA-256. Every title, body, label, base, head,
    repository, or bound-review change invalidates prior evidence and requires fail-closed revalidation; it MUST NOT
    request AI again merely because metadata changed.
11. Contributor-funded fork reviews MAY be verified, but the Lightning IT-funded request job remains same-repository
    and `litroc`-only. The verifier MUST preserve and bind the actual head repository instead of silently rewriting
    fork identity to the base repository.
12. Local deterministic checks MUST use the digest-pinned Devtools container with an offline network, read-only
    root filesystem and workspace, the invoking non-root UID/GID, all capabilities dropped, and
    `no-new-privileges`. The host Docker-compatible socket MAY be used only to start that container and MUST NEVER
    be mounted into it. A scenario that needs a managed runtime belongs to a protected pipeline and MUST fail closed
    locally instead of weakening this boundary.

## 1.3 LI-219 Three-Pilot Adoption (2026-10-05)

LTN-360 retires the inactive workflow files and their exclusive reconciler listed
in `.lit/li259-supplementary-port.json` under `dormant_retirement`. The historical
LI-219/LI-259 descriptions below do not authorize recreating those retired files.
The surviving producer, current-revision helpers, consumed-review records and
documented transition routes retain their existing checks and limits.

This owner-authorized local adoption is restricted to `lightning-it/.github`,
`lightning-it/shared-assets-lit`, and `lightning-it/ansible-collection-supplementary`.
The event behavior requires the exact repository variable `LI219_EVENT_MODE=enabled`.
Absent or disabled flags retain legacy execution. Fleet admission remains frozen.

The Supplementary producer remains repository-owned. Its exact protected source
checks, Release-App exclusion, ancestry-only exemption, Renovate restrictions,
fork identity, metadata/label binding, and branch-specific legacy helper routes
remain local contracts. The bounded port adopts the audited Source request claim,
refresh, helper and reconciler. This explicit adoption does not authorize a generic
sync to overwrite the producer or Security release and main-authorization files.
The independent DotGithub verifier retains its native promotion-aggregation checks.

Events locate evidence; protected consumers independently authorize mutations.
The request consumes one repository-ID/PR/head CAS operation on
`refs/heads/lit-review-operations` before its sole POST. Uncertain outcomes never
permit a blind retry. The event refresh may consume the sole producer rerun;
the request job is attempt-one-only. The helper validates the completed producer
attempt and full Required inventory before the sole verifier rerun. CAS receipts
never replace native review evidence. Terminal review content consumes no retry.

The canonical donor is protected Source MAIN `a44cb1762aa6ae3edba91d6cf75ada2a99182af5`
(tree `77c0ecbb1c4b62276c4e61e7a6cc9a15cd8b8762`), adopted through the actual protected Main merge.
`.lit/li219-pilot-source.json` and `.lit/li219-gateway-source.json` bind the immutable
Source blobs, target digests, and protected adoption receipt. This local Port has
not yet received independent or native acceptance; event activation remains separate.
The original Supplementary request job keeps its six-job producer
context and exact source/author/actor predicate. Only the enabled three pilots
admit `synchronize`. PR-wide Pending writes a separate immutable deferred intent,
never an accepted-head marker or a consumed request claim. An unconfirmed original
POST also must not publish an accepted marker; a consumed claim remains consumed.

New deferred eligibility uses typed intent schema2: source_ref/source_sha bind the original
protected default develop execution, while base_ref/base bind the independent PR target.
The request receipt keeps the later base-controller source_sha separate from its nested
original intent. Legacy schema1 binds its original protected default develop source independently
of the PR base. New continuations use the exact PR base controller for both schemas;
historical schema1 receipts may bind an authentic protected develop resume source.
Exact live controller and PR-base fences apply before/after eligibility CAS, and before
request CAS and after CAS/before POST; unknown writes remain consumed/readback-only.
Ordinary human fork verification/handoff/refresh preserves native head repository identity;
funded requests and continuations remain same-repository and litroc-only.

The protected first-request continuation validates that original intent and native
request steps, the completed old-head review, current PR/source identity and all
existing budgets. Its schema-2 receipt consumes the SAME repository-ID/PR/head
request key; either schema-1 or schema-2 presence blocks another request. Review
and owner-completion events only locate work; completed `Copilot` and
`Running Copilot Code Review` events also only wake the protected inventory locator; the existing ten-minute reconciler
is the bounded delayed-visibility fallback. All three dispatch workflow families
share the existing 256-GET inventory budget and native cooldown. The original
producer remains the owner; LI-219 alone adds no third verifier attempt. The
separately enabled, sealed LI-259 exception below is its only bounded extension.
The exact-review SINGLE gateway is distributed with its workflow, materializer,
and all six runtime modules, including single_review_resources.py. The protected-source and final local instruction digests are content-bound; native
acceptance remains pending.

The repository-owned Push-Ready engine retains Supplementary classification,
full-index patch shape, local Git/source guards and no-AI behavior. It adopts the
canonical complete streaming path and aggregate 500000000-byte tracked-workspace
read budget; this is not a PR or diff-size ceiling. Its adapted target digest is
explicitly recorded. The canonical pilot installer retains its earlier allowlisted
engine; the scoped local adapter is applied after that installer without changing
Source. Existing canonical-file lint exceptions remain limited to the materializer.

The adjacent continuation module and read-only provenance module are explicit
scoped managed assets. Locator jobs receive read access plus dispatch authority;
only the protected consumer receives the audited request/CAS write scopes.

Only an exact confirmed native STALE_DATA journal conflict permits retrying the
eligibility-only intent write, with at most three attempts. Unknown delivery is
readback-only; request CAS and AI POST remain single-attempt. Legacy uncertain request
consumption survives cleared Pending and terminal review content; it never funds
a second same-head request. Explicit negation (including ASCII and U+2019 apostrophes in isn't) marks
failure; positive able-to-review text does not. Keyed inventories
require stable exact totals. Historical review provenance uses its bound request
event time, authenticated inside the native request step. Supplementary has no protected empty-association sender:
an empty native PR association fails closed in original/continuation/provenance
callers. Existing fully bound nonempty associations retain their original route.

The required static Contents/Checks write scopes apply only to the audited jobs;
legacy helper jobs retain read scopes. Workflow token permissions remain
repository-wide. Enable only after protected source/target controllers and the
CAS manifest/rules are verified and old/new writers are quiesced and drained.
Rollback also drains writers and preserves consumed operations.

Normal Copilot PR size is advisory: Push-Ready version 3 retains its existing risk
classification and protected-policy binding, using `review.warn_diff_bytes: 500000`.
Legacy positive `max_diff_bytes` remains readable without imposing a diff ceiling.
Null disables the notice. Full deterministic checks and complete input remain
mandatory; no automatic splitting, truncation or additional AI review follows.
Per-file safe-read limits, historical evidence schemas and model-call contracts
remain separate. No new model-call route is introduced by this pilot.

`.lit/li219-pilot-source.json` preserves the original protected Source MAIN
adoption and its historical local hashes. Later LI-259 changes are bound to
protected Source MAIN and the current local bytes in
`.lit/li259-supplementary-port.json`; a local feature-source hash is not
protected rollout authority. The scoped current inventory
`.lit/li219-managed-assets.json`, validated by the pilot contract tests,
distinguishes byte-identical source assets from locally adapted contracts. It
does not opt the collection into a repository-wide managed inventory or fleet sync.

## 1.4 LI-259 Bounded Native Verifier Recovery

The owner-authorized exception applies only with `LI219_EVENT_MODE=enabled` and
`LI259_INFRA_RETRY=enabled`, after coupled protected Source/Core adoption. Only
prospectively sealed supplementary verifier attempts 3 and 4 may recover the
classified native hosted-runner acquisition failure. Keep the identical review,
repository, PR, base, head, controller, policy and input bindings; separate durable
technical claims from event deduplication. Cooldowns remain 20/40 minutes, the
sealed total budget 180 minutes, and the start reserve 60 minutes. Claim-to-POST
visibility gaps are bounded GET-only pending; unknown writes never repeat.
Observed drift, deterministic failures and exhausted feasible budgets are terminal.
No recovery creates AI requests, pushes, PRs or reviewed revisions. The separate
former cross-controller receiver is now owned by the central `.github` source
under LI-319; Supplementary no longer distributes or executes that authority.
Existing unsealed runs gain no authority, and activation still requires genuine
native acceptance.

### LI-319 central verification ownership

The owner-authorized migration makes public `lightning-it/.github/main` the sole
central verifier source. Live ruleset 21200954 was switched through the protected
private Management path after overlapping mandatory enforcement and native
one-person acceptance. Supplementary remains a consumer of unchanged rule
20938748 and owns its Collection, compatibility, security and release gates.
One authorized person may approve their own initiated operation through the
native self-reviewable environment; no second human approval is required.

The retired local counter-verifier, its dedicated tests and its three active
managed-inventory entries must not be regenerated. Their exact prior blobs and
historical LI-219/LI-259 bindings are recorded in
`.lit/li319-central-verifier-retirement.json`; historical source receipts remain
unchanged. Only explicitly bound current policy updates supersede old policy
hashes. Existing review consumption, technical retry limits and release evidence
are preserved. Private administrative credentials never enter this repository.

## 2. Repository Baseline (This Repo)

1. Repository identity values (namespace, name, license, tags, dependencies) MUST be read from `galaxy.yml`.
2. Do not copy identity metadata from another collection repository.
3. Linting uses 120-character YAML line length:
   1. `.yamllint` max line length 120
   2. `ansible-lint.yml` YAML max line length 120
4. Pre-commit runs devtools-based hooks for `yamllint`, `ansible-lint`, and Molecule light scenarios.

## 2.0.1 Release and Changelog Rules (Mandatory)

1. Ansible collection changelog handling MUST stay repository-based.
2. NEVER replace Ansible collection changelog files with GitHub Release notes only.
3. Ansible collection releases MUST NOT use `semantic-release`.
4. `semantic-release` remains allowed for non-collection repositories only.
5. If a repository has `galaxy.yml` and collection structure such as `roles/`, `plugins/`, or `playbooks/`,
   treat it as an Ansible Collection repository.
6. Shared release workflow logic belongs in `shared-assets-lit` and is rendered into local collection workflows.
7. Use `antsibull-changelog` for collection changelogs:
   1. fragments live under `changelogs/fragments/`,
   2. generated changelog metadata lives in `changelogs/changelog.yaml`,
   3. generated release notes live in `CHANGELOG.rst`.
8. Every user-visible feature, fix, deprecation, removal, security fix, or known issue MUST add a fragment under
   `changelogs/fragments/<meaningful-name>.yml`.
9. Normal feature/fix PRs MUST NOT manually edit generated changelog files:
   1. `changelogs/changelog.yaml`,
   2. `CHANGELOG.rst`,
   3. legacy `CHANGELOG.md` files where they still exist.
10. Generated changelog files and `galaxy.yml` version bumps are release-PR changes only.
11. Release preparation MUST happen on `release/vX.Y.Z` branches. Normal Supplementary preparation uses protected
    Main tooling against the exact bound Develop data and opens its PR into `develop`; the subsequent ordinary
    protected Develop-to-Main promotion supplies the release revision. The separately governed Security route
    retains its direct-to-`main` preparation. Follow `RELEASE.md` for the required convergence and evidence steps.
12. The release preparation workflow MAY automatically create that PR after a push to `main` when unreleased
    changelog fragments exist.
13. Publishing happens only after the release PR is merged into `main`.
14. No workflow or agent may push release commits directly to `main`.
15. After a release is published from `main`, release-generated files MUST be synced back to `develop` with a
    `backsync/release-vX.Y.Z-to-develop` PR before any new `develop` to `main` promotion.
16. A `develop` to `main` promotion MUST only be opened when `main` is an ancestor of `develop`.
17. GitHub Release notes are an additional publishing surface; they MUST be generated from or aligned with the
   repository changelog, not used as the only changelog.
18. GitHub repository settings, branch protection, required checks, workflow permissions, labels, environments,
    secrets, and release-bot permissions MUST be changed only through `github-management-lit`.

## 2.1 Production Review Standard (Community, Red Hat, Efficiency)

Use this standard when reviewing, creating, or changing collection content. Treat it as the baseline audit prompt for
production readiness, Ansible Galaxy readiness, and Red Hat Ansible Automation Platform readiness.

### 2.1.1 Collection Structure and Metadata

1. Verify correct collection layout and naming under the repository root.
2. Keep `galaxy.yml` complete and accurate: namespace, name, version, README, description, repository, authors,
   license, tags, dependencies, and `build_ignore`.
3. Keep `meta/runtime.yml` aligned with the supported Ansible range.
4. Keep README, Ansible collection changelog files, examples, role docs, and licensing suitable for publication.
5. Ensure collection dependencies are declared once in `galaxy.yml` unless this guide documents an overlay exception.

### 2.1.2 Ansible Community Best Practices

1. Roles and playbooks MUST be idempotent.
2. Use FQCNs for modules and plugins.
3. Prefer purpose-built modules over `ansible.builtin.command` or `ansible.builtin.shell`.
4. When command or shell tasks are justified, define precise `changed_when` and `failed_when` behavior.
5. Support check mode and diff mode where the underlying operation can do so safely.
6. Keep task names specific, variables role-prefixed, defaults clear, and handlers explicit.
7. Avoid hardcoded hosts, users, credentials, private URLs, site-specific paths, and environment-specific values.
8. Prefer structured module parameters and filters over ad hoc string parsing.

### 2.1.3 Red Hat and Enterprise Readiness

1. Content SHOULD run predictably in Red Hat Ansible Automation Platform and execution environments.
2. Avoid dependencies that cannot be resolved in the repository's default public CI/runtime path.
3. Keep entitlement-gated dependencies out of collection metadata and document the consumer/workspace overlay instead.
4. Do not require controller credentials, Red Hat credentials, or private infrastructure for public lint and unit gates.
5. Document supported platforms, required privileges, external services, and operational boundaries.
6. Keep examples realistic for controller-based automation and CI/CD use.

### 2.1.4 Testing and Quality Gates

1. `pre-commit run --all-files` MUST be the first local PR preflight for collection repositories. Shared hooks run
   the PR-equivalent changelog, ansible-lint, socket-free `artifacts-basic` parity, and smoke gates through
   `ee-wunder-devtools-ubi9`; dependency-backed role matrices remain mandatory protected pipeline gates.
2. `ansible-lint --profile production .` SHOULD pass, or repository-specific devtools lint MUST pass with documented
   equivalent strictness.
3. `ansible-test sanity --docker` SHOULD pass for custom modules/plugins and collection packaging concerns.
4. Unit tests SHOULD cover custom modules, plugins, filters, and module_utils helpers.
5. Integration tests SHOULD cover real behavior, failure cases, idempotency, check mode, and upgrade paths.
6. Molecule scenarios SHOULD cover role behavior with converge, idempotence, and verify.
7. CI SHOULD run lint, sanity, unit, integration, package build, and smoke install where practical.
8. For PR or CI fixes, reproduce the failing gate locally first and do not rely on GitHub Actions as the first
   end-to-end verifier. Run the repository devtools gates from the repo root before finalizing whenever the
   needed runtime is available. Docker or Podman is sufficient for the default public gates; protected or heavy
   Incus scenarios additionally require an accessible Incus daemon and suitable images.

Required local PR gates for collection changes, when the scripts exist:

```bash
pre-commit run --all-files
bash scripts/devtools-ansible-lint.sh
bash scripts/devtools-molecule.sh
bash scripts/devtools-collection-smoke.sh
bash scripts/devtools-changelog-check.sh
```

Recommended commands when applicable:

```bash
ansible-lint --profile production .
ansible-test sanity --docker
ansible-test units --docker
ansible-test integration --docker
ansible-galaxy collection build .
ansible-galaxy collection install ./<built-artifact>.tar.gz --force
```

### 2.1.5 Code Efficiency and Maintainability

1. Avoid repeated expensive lookups, package queries, fact gathering, API calls, and templating loops.
2. Disable or scope fact gathering when facts are not needed.
3. Cache reusable data with registered variables or facts when that is clearer and cheaper.
4. Use efficient loops, filters, pagination, retries, timeouts, and backoff for API-driven roles.
5. Put repeated Python logic in `module_utils` and repeated role logic in focused task files or roles.
6. Keep module argument specs explicit and return values predictable.
7. Keep YAML readable, sorted where the repo already sorts, and free of duplicated blocks that should be shared.

### 2.1.6 Security Review

1. No secrets, tokens, passwords, keys, private URLs, or sensitive inventory values may be committed.
2. Use `no_log: true` for tasks handling sensitive values, while still keeping debuggability where safe.
3. Quote shell inputs and avoid command injection risks.
4. Do not use unsafe `eval`, `exec`, or template expansion patterns.
5. Validate TLS certificates by default. Any opt-out MUST be explicit, documented, and narrowly scoped.
6. Apply least-privilege defaults for users, files, services, API tokens, and controller objects.

### 2.1.7 Review Output Format

When asked for a review, report findings in this order:

1. Executive summary: production-ready, nearly ready, or not ready.
2. Critical findings: deployment breakers, security risks, or publication blockers.
3. Major findings: correctness, idempotency, compatibility, maintainability, or testing gaps.
4. Minor findings: style, naming, documentation, or polish.
5. Efficiency improvements.
6. Security review.
7. Testing gaps.
8. Recommended fix plan.

For each finding, include severity, file and line, why it matters, recommended fix, and example corrected code when useful.

## 2.2 Collection Dependency Management (Mandatory)

1. Collection dependency source of truth is `galaxy.yml` `dependencies`.
2. When role code starts using modules/plugins from another collection, you MUST add that collection to
   `galaxy.yml` immediately.
3. Collection dependency versions MUST be maintained in `galaxy.yml`; do not duplicate version ownership in
   `collections/requirements.yml`.
4. `galaxy.yml` dependencies MUST stay installable in the repository's default public CI/runtime path.
5. Entitlement-gated dependencies (for example Red Hat Automation Hub-only collections) MUST NOT be declared in
   collection `galaxy.yml`; manage them in consumer/workspace overlay requirements instead.
6. If `collections/requirements.yml` exists, it is an overlay input only (workspace/runtime packaging). It MUST
   NOT become the canonical source of versions for dependencies already declared in `galaxy.yml`.
7. Renovate in collection repos SHOULD track `galaxy.yml` dependencies only; requirements-file managers SHOULD be
   limited to documented overlay-only exceptions.
8. If dependency update policy differs per dependency (for example lifecycle-managed collections), encode that as
   targeted Renovate `packageRules` while keeping version ownership in `galaxy.yml`.

## 2.3 Package Version Management (Mandatory)

1. Repository-owned package/tool dependency versions MUST be fixed to explicit versions wherever the repository is
   the source of truth for that version.
2. Do not introduce open-ended or floating version ranges such as `>=`, `<=`, `~=`, `^`, or `latest` unless the
   repository already requires that pattern or the user explicitly asks for it.
3. When a package version is maintained outside `galaxy.yml` (for example in `requirements.txt`,
   `.pre-commit-config.yaml`, `package.json`, or tool-specific config), Renovate SHOULD manage that version.
4. When adding a new repo-managed package version, you SHOULD also add or confirm Renovate coverage for that file
   and dependency.
5. Do not create parallel version ownership for the same dependency across multiple files unless the repository
   explicitly documents that split.

## 2.4 Ansible Collection Renovate and Release Policy

For Lightning IT Ansible collection repositories, follow the shared Renovate and release model.

Do not hand-maintain generic Renovate policy in individual collection repositories. Generic Renovate rules must be
maintained in `lightning-it/shared-assets-lit` and rendered into each repository's local `renovate.json`.

Collection repositories may only define repository-specific Renovate overrides, such as:

- temporary version pins
- compatibility constraints
- collection-specific package rules
- local custom managers that are not reusable

The standard branch and release model is:

- `develop` is the automated integration branch.
- Renovate targets `develop`.
- Safe patch, minor, pin, and digest updates may auto-merge into `develop` after required CI passes.
- Major updates require manual approval.
- `main` is the stable release branch.
- Promotion from `develop` to `main` must happen through a pull request.
- Promotion pull requests must remain a human-visible manual merge checkpoint after required checks pass.
- Do not direct-push from `develop` to `main`.
- Collection release PRs are created automatically from `release/vX.Y.Z` branches after `main` receives unreleased
  changelog fragments.
- Release PRs target `main` and must pass required checks before merge.

Automation safety requirements:

- Protected branches must require pull request review.
- Only trusted Renovate PRs may be enabled for auto-merge by collection automation after all required current-head checks pass. The protected `develop` branch requires zero approving reviews; GitHub Actions reviews remain disabled by governance.
- A trusted Renovate PR must have `renovate[bot]` as both trigger actor and PR author, a `renovate/*` source
  branch, `develop` as the base branch, and both `renovate` and `dependencies` labels.
- Human, external contributor, and develop-to-main promotion PRs must not be auto-approved or auto-merged by
  collection automation.
- Do not use `pull_request_target` for Renovate approval or merge automation.

## 3. Role Variable Naming and Mapping Rules

### 3.1 Role-Prefixed Variables (Mandatory)

1. Variables defined and owned by a role MUST use that role prefix in snake_case.
2. Format: `<role>_<name>`.
3. Examples:
   1. `selinux_state`, `selinux_policy`
   2. `keycloak_config_skip_apply`, `keycloak_config_tg_dir`
4. You MUST NOT bypass variable naming rules with lint suppressions (for example `# noqa var-naming`).

### 3.2 Secrets Variable Naming (Mandatory)

Secret and Vault-related variables MUST also be role-prefixed.

Required pattern (adapt per role):

1. `<role>_use_vault`
2. `<role>_vault_addr`
3. `<role>_vault_token`
4. `<role>_vault_role_id`
5. `<role>_vault_secret_id`
6. `<role>_vault_kv_mount`
7. `<role>_vault_kv_path`

Example:

```yaml
myrole_use_vault: true
myrole_vault_addr: "{{ vault_address | default('') }}"
myrole_vault_token: "{{ vault_token | default('', true) }}"
```

### 3.3 Canonical Mapping Rule (No Semantic Renaming)

This rule is about naming and mapping only. It is NOT a mandate to refactor all existing code at once.

1. If a value originates from another role/component, defaults MUST map from the source variable name.
2. You MUST keep one canonical semantic variable name for a setting.
3. You MUST NOT introduce secondary aliases that rebrand the same setting.

Bad:

```yaml
myrole_bootstrap_bucket: "{{ myrole_config_bucket }}"
myrole_config_bucket: "{{ myrole_bootstrap_bucket }}"
```

Good:

```yaml
myrole_bucket: "{{ myrole_bucket | default('vault-bucket', true) }}"
myrole_bucket_effective: "{{ myrole_bucket | default(otherrole_bucket, true) }}"
```

For cross-role inputs, preserve producer naming and avoid translation layers.

```yaml
myrole_api_url_effective: "{{ myrole_api_url | default(minio_deploy_api_url_effective, true) }}"
```

### 3.4 Role Type Naming: `_config` vs `_cac` (Mandatory)

1. Use `<role>_config` for host-local/service-local configuration concerns:
   1. local files/templates
   2. local service/unit/runtime settings
   3. config materialization on managed hosts
2. Use `<role>_cac` for configuration-as-code object orchestration:
   1. API-driven object management (for example AAP objects)
   2. declarative object sync/reconciliation flows
   3. composition of multiple object tasksets
3. If both patterns are needed, they MUST be split into separate roles (`*_config` and `*_cac`).
4. Feature role naming for CaC MUST use the suffix `_cac` (example: `aap_cac`).
5. In `*_cac` roles, taskset entrypoint files MUST use the `cac_` prefix:
   1. valid: `cac_11_gateway_organizations.yml`
   2. invalid for tasksets: `playbook_05_gateway_organizations.yml`
6. Helper/internal tasks in `*_cac` roles MUST NOT use the `cac_` prefix
   (example: `create_authentication_token.yml`, `delete_authentication_token.yml`).

### 3.5 Service Lifecycle Role Family Layout

For service/application lifecycle roles, prefer this role family layout:

```text
<service>                  # optional meta/orchestrator
<service>_preflight        # host/input/dependency checks
<service>_deploy           # install/runtime deployment
<service>_config           # runtime config files/settings
<service>_cac              # configuration-as-code/API object reconciliation, when applicable
<service>_validate         # health/API/state validation
<service>_ops              # status/restart/rotate/day-2 operations
<service>_backup_restore   # backup and restore
<service>_upgrade          # version/image upgrade flow
<service>_destroy          # protected teardown
```

Use only applicable roles. For databases such as PostgreSQL, omit `_cac` by default unless there is real declarative
object reconciliation.

All managed application-container configuration MUST be rendered as Kubernetes YAML suitable for `podman kube play`;
Compose files and imperative container definitions are not permitted deployment sources. New or changed persistent
runtimes MUST be started and owned exclusively through a native Quadlet `.kube` unit managed by
`lit.foundational.podman_systemd`. Startup, enablement, restart, stop, and removal MUST go through the
Quadlet-generated service. A role MUST NOT invoke `lit.foundational.kubeplay` or `podman kube play` directly while
Quadlet/systemd management is enabled; doing so creates two competing lifecycle controllers. Direct
`lit.foundational.kubeplay` is permitted only for an explicit non-systemd test/manual mode, a documented
compatibility exception where Quadlet is unavailable, or an emergency operation. Such an exception MUST be
fail-closed, narrowly scoped, and covered by regression evidence. Ephemeral Devtools and CI containers are execution
environments, not managed application deployments, and therefore do not require persistent Quadlet units.
Legacy wrappers are debt; changes MUST migrate them or document an exception.

## 4. Role Structure and Prechecks

### 4.0 Role Responsibility Boundaries

1. Keep operating-system preparation in the operating-system collection:
   1. users and groups
   2. sudoers policy
   3. packages and repositories
   4. RHSM registration
   5. Podman installation and rootless storage
   6. generic Ansible remote temporary directories
2. Application roles MUST consume prepared OS state and validate it, not create
   or repair it. For example, AAP roles may validate the `aap` install user and
   required commands, but user creation belongs to `lit.rhel.users`.
3. Artifact discovery, download, checksum verification, and staging belong in a
   dedicated prepare/artifacts role. Deploy roles SHOULD consume final prepared
   paths and avoid parallel fallback discovery logic.
4. Avoid repeated near-identical task branches for source variants such as
   `url`, `local`, and `remote`. Resolve source-specific values once, build one
   normalized item, and pass that normalized item to the generic implementation.
5. Compatibility wrappers for misspelled role names or legacy aliases are
   temporary. Remove them once no maintained playbook, runbook, Molecule
   scenario, or documentation references them.

### 4.1 Required Role Layout

Roles SHOULD follow:

```text
roles/<role_name>/
  README.md
  defaults/main.yml
  tasks/main.yml
  tasks/assert.yml
  meta/main.yml
  handlers/main.yml        # optional
  templates/               # optional
  files/                   # optional
```

Role directory names MUST be snake_case.

### 4.2 Precheck Entrypoint

1. `tasks/assert.yml` MUST exist for new or actively maintained roles.
2. `tasks/main.yml` MUST import `assert.yml` first with `tags: always`.
3. `assert.yml` MUST be side-effect free:
   1. validate input types/required variables/invariants
   2. no system mutation
   3. no Vault/API calls

Required pattern:

```yaml
---
- name: Prechecks
  ansible.builtin.import_tasks: assert.yml
  tags: always
```

### 4.3 Precheck Responsibility Boundaries (Critical)

1. `assert.yml` for a role MUST validate that role's interface, not another role's internals.
2. In `roles/<role>/tasks/assert.yml`, assertions SHOULD target `<role>_*` variables only.
3. Non-deploy roles (`*_ops`, `*_validate`, `*_config`, `*_bootstrap`, `*_backup_restore`) MUST NOT
   assert raw `*_deploy_*` variables directly.
4. If a role needs values originating from another role, map them in `defaults/main.yml` into role-prefixed
   runtime vars, then assert those mapped vars.
5. `assert.yml` in one role MUST NOT import another role's `tasks/assert.yml` unless explicitly required by
   repository design and documented in that role README.
6. Action-based roles MUST use action-scoped assertions:
   1. `*_action == 'none'`: validate only action enum and basic booleans.
   2. `restart/reload`: validate service or pod identifiers.
   3. `status`: validate health/status endpoint vars.
   4. `upgrade`: validate target image/package inputs.

Bad (cross-role coupling in role assert):

```yaml
- name: Ensure nginx_ops variables are valid
  ansible.builtin.assert:
    that:
      - nginx_deploy_systemd_unit_name | length > 0
      - nginx_deploy_pod_name | length > 0
```

Good (mapped in defaults, asserted in role namespace):

```yaml
# defaults/main.yml
nginx_ops_systemd_unit_name: "{{ nginx_deploy_systemd_unit_name | default('', true) }}"
nginx_ops_pod_name: "{{ nginx_deploy_pod_name | default('', true) }}"
```

```yaml

# tasks/assert.yml
- name: Ensure restart variables are set for systemd mode
  ansible.builtin.assert:
    that:
      - nginx_ops_systemd_unit_name | default('', true) | trim | length > 0
  when:
    - nginx_ops_action == 'restart'
    - nginx_ops_manage_systemd | bool
```

7. Foundational/helper roles MUST only assert variables required for their own task scope. Do not enforce
   endpoint/runtime vars in foundational prechecks if the role only resolves credentials.

### 4.4 FQCN Modules

1. Tasks MUST use FQCNs (`ansible.builtin.*` or collection FQCNs).
2. Example:

```yaml
- name: Create config directory
  ansible.builtin.file:
    path: /srv/example
    state: directory
    mode: '0750'
```

## 5. Defaults and Derivations

1. Static defaults and pure derivations SHOULD live in `defaults/main.yml`.
2. Use derived variables such as `*_effective`, `*_enabled`, `*_manage_*` where helpful.
3. Do not use `set_fact` for values that can be computed in defaults.
4. Runtime discovery from remote state, commands, APIs, or Vault MUST stay in tasks, not defaults.

## 5.1 Public Reusability and Environment Neutrality

1. Roles MUST be publicly reusable and environment-agnostic by default.
2. Role code (`defaults/`, `tasks/`, `templates/`, `README.md`) MUST NOT hardcode environment-specific values.
3. Environment-specific variables are NOT permitted in role defaults, including:
   1. internal domains
   2. inventory hostnames or FQDNs tied to one environment
   3. environment-only URLs, tokens, or credentials
4. Use neutral defaults and placeholders, then inject real values from inventory/group vars/playbooks.
5. If a role needs an address/domain, expose a generic role variable and keep the default generic or empty.
6. Environment specialization belongs in consumer inventory/playbooks, not reusable role defaults.

Bad:

```yaml
myrole_server_name: "vault.prd.dmz.corp.l-it.io"
myrole_api_url: "https://vault01.prd.dmz.corp.l-it.io:8200"
```

Good:

```yaml
myrole_server_name: "vault.example.com"
myrole_api_url: ""
myrole_api_url_effective: >-
  {{
    myrole_api_url
    if (myrole_api_url | default('', true) | length > 0)
    else ('https://' ~ myrole_server_name)
  }}
```

## 6. Idempotency and Check Mode

1. Prefer idempotent modules over `shell`/`command`.
2. If `shell`/`command` is required, you MUST control idempotency with at least one:
   1. `creates` or `removes`
   2. `changed_when` and `failed_when`
   3. explicit state pre-check + conditional apply
3. Read-only tasks MUST set `changed_when: false`.
4. Check mode behavior MUST be explicit for mutating tasks that cannot run in check mode.

Example:

```yaml
- name: Read current state
  ansible.builtin.command: mytool status
  register: myrole_status
  changed_when: false

- name: Apply state when needed
  ansible.builtin.command: mytool apply
  when:
    - not ansible_check_mode
    - myrole_status.stdout != 'ready'
  changed_when: true
```

## 7. Secrets and Logging Policy

1. Secrets MUST NOT be printed in debug output.
2. Tasks handling secrets MUST set `no_log: true`.
3. Vault responses and secret payloads MUST NOT be logged.
4. Secret values MUST NOT be written to artifacts, generated docs, or committed test output.
5. If failure output can expose secrets, task-level `no_log: true` MUST still be used.

### 7.1 Secret Source of Truth and Password Lifecycle (Mandatory)

1. Each environment MUST have exactly one declared source of truth for runtime passwords:
   1. external secret manager (for example HashiCorp Vault), or
   2. inventory variables (preferably encrypted via Ansible Vault).
2. Password generation is allowed only when the value can be persisted immediately to the selected source of truth.
3. Generating a password without persistence is NOT allowed for deployment flows.
4. If a required password is missing and cannot be persisted, the role/play MUST fail fast.
5. Secret resolution order MUST be deterministic and documented:
   1. explicit role input variable,
   2. secret manager read (when configured),
   3. inventory-provided value,
   4. generate and persist to configured backend,
   5. fail if none of the above is possible.
6. Rotation MUST be explicit (for example action-driven), and MUST update source of truth first, then apply change to the target service.
7. Idempotency requirement: repeated runs with unchanged inputs MUST resolve the same effective secret values.
8. Local file cache may be used only as an explicitly documented lab/offline fallback and MUST NOT replace a declared production source of truth.

Example:

```yaml
- name: Read credentials from Vault
  community.hashi_vault.vault_kv2_get:
    url: "{{ myrole_vault_addr }}"
    token: "{{ myrole_vault_token }}"
    engine_mount_point: "{{ myrole_vault_kv_mount }}"
    path: "{{ myrole_vault_kv_path }}"
  register: myrole_secret
  no_log: true
```

## 8. Molecule Standards

### 8.0 Test Ownership Boundary (Mandatory)

This collection owns reusable role implementation, Tiny coverage, and environment-neutral scenario logic.
`lightning-it/modulix-validation` is the public validation repository and owns the workflow orchestration for
protected Incus, Heavy, live, nightly,
cross-service, and Application Acceptance execution, including matrices, runner contracts, protected environments,
secrets, finalizers, and evidence retention.

The `-lit` suffix is reserved for private repositories. Do not add it to references to this public validation
repository.

Do not add new self-hosted Heavy or Application Acceptance matrices directly to collection workflows. A collection
release gate MAY call a reusable workflow from `modulix-validation` so the exact collection candidate remains
fail-closed without duplicating private infrastructure orchestration here. Scenario sources MAY remain in this
repository when they are reusable and tightly coupled to role behavior.

Names such as `*_heavy`, `*-heavy`, `*-application-acceptance`, `*_live_*`, and
`.molecule-mode: protected-incus` MUST route execution through `modulix-validation` unless a documented exception
proves that the scenario is lightweight and uses no protected infrastructure.

### 8.1 Location

Molecule scenarios MUST live at repository root under `molecule/`.

### 8.2 Naming and Profiles

1. Existing `-basic` and `_heavy` scenarios are legacy scenarios. They may remain while experimental coverage is
   migrated, but they MUST NOT be represented as production Tiny, Heavy, or Application Acceptance coverage unless
   their behavior meets the corresponding profile policy below.
2. New component profile scenarios MUST use:
   1. `<component>-tiny`
   2. `<component>-heavy`
   3. `<component>-application-acceptance`
3. Closely coupled deploy and CaC roles MAY share one component scenario when every role has separately reported test
   cases and an explicit registry declaration.
4. Large playbooks MUST be shared through imported playbooks under `molecule/shared/`; do not use fragile symlinks.

### 8.3 Execution Behavior

1. `scripts/devtools-molecule.sh` defaults to the offline, socket-free `artifacts-basic` controller parity scenario.
   An explicitly named unmanaged scenario may run only if the pinned image already contains every dependency. The
   host-native profile runner and CI matrix run the full dependency-backed and protected Incus Tiny, Heavy, and
   Application Acceptance scenarios.
2. Scenarios with `.molecule-mode` set to `protected-incus` are skipped unless
   `MOLECULE_RUN_PROTECTED=true` is set and the devtools container has the `incus` CLI.
3. A single scenario is run with:

```bash
scripts/devtools-molecule.sh minio-config-basic
```

4. Keep light scenarios runnable in devtools and pre-commit without external infrastructure.

### 8.4 Mandatory Role Quality Lifecycle

<!-- role-quality-governance:start -->

Every future role and every material role change MUST follow this lifecycle:

```text
implementation
-> documentation
-> linting
-> Tiny
-> Heavy
-> Application Acceptance
-> evidence
-> CI integration
-> release validation
```

A role is not complete merely because its tasks execute or an Ansible play returns zero.

1. `meta/role-coverage.yml` is the authoritative inventory for every directory under `roles/`, every root Molecule
   scenario, maturity, platform support, dependencies, blockers, acceptance surface, and profile disposition.
2. Every role MUST explicitly declare Tiny, Heavy, and Application Acceptance. Profiles MUST never be omitted.
3. Allowed profile states are `supported`, `experimental`, `not-applicable`, `blocked-external-service`,
   `blocked-external-license`, `blocked-external-infrastructure`, and `deprecated`.
4. A blocked, experimental, or deprecated role MUST NOT be described as fully production-tested.
5. New production roles MUST NOT be empty stubs. A Stub-only or Skip-mode-only scenario is insufficient.
6. A new or materially changed role MUST update the registry and generated coverage documentation in the same change.

### 8.5 Tiny Policy

Every production-supported role MUST have a fast Tiny scenario that uses the real role and validates, as applicable:

1. variables and argument specifications;
2. expected packages, images, files, permissions, users, groups, services, containers, or resources;
3. readiness and basic authenticated API, protocol, database, network, or CLI behavior;
4. application or component version;
5. secure permissions and secret safety;
6. idempotency; and
7. cleanup.

Tiny MUST NOT pass merely because runtime installation or role execution was disabled.

### 8.6 Heavy Policy

Every production-supported role MUST have a production-like Heavy scenario using the intended deployment path. It
MUST validate every applicable operational behavior, including dependencies, persistent storage, TLS, networking,
database or directory integration, authentication, restart recovery, reconciliation, backup and restore, supported
upgrade behavior, related-role integration, secret handling, and idempotency. A mock or stub is not production Heavy
coverage.

### 8.7 Application Acceptance Policy

Every production-supported role MUST have a real consumer-facing Application Acceptance scenario. The surface MUST
match the component: browser and API, authenticated API workflow, database client, log ingestion and query,
monitoring discovery and query, network connection and traffic, agent data delivery, runner workload, backup and
restore, configuration reconciliation, or a safe infrastructure operation.

1. Positive and negative behavior are mandatory.
2. Authorized access MUST succeed and unauthorized or invalid access MUST fail at the API, CLI, protocol, protected
   endpoint, database, or network layer.
3. UI visibility, rendered variables, process existence, ignored command failures, skipped installation, or a stub
   success marker are not acceptance evidence.
4. CaC roles MUST apply desired state to a real application, query actual state, prove idempotency, reconcile a
   change, and verify deletion where supported.

### 8.8 Verify, Reporting, and Evidence Policy

1. `verify` is mandatory in every Molecule scenario and MUST test externally observable behavior. Converge alone is
   never a pass.
2. Every applicable scenario MUST emit meaningful per-assertion JUnit and Allure results, redacted logs, environment
   metadata, tool and application versions, commit identity, target parameters, and result status.
3. Browser failures MUST retain sanitized screenshots, Playwright traces, console logs, and network diagnostics.
4. Protocol, API, CLI, and database tests MUST retain a redacted operation summary, result, client version, and
   assertion result.
5. Heavy and Application Acceptance runs MUST create structured evidence for both success and failure where
   technically possible. A mandatory skip is not a pass.
6. Evidence MUST include checksums and an automatically calculated `release_eligible` value derived from actual
   results; it MUST NOT be a manually edited assertion.

### 8.9 Incus Policy

Incus scenarios MUST use unique repository, run, attempt, component, profile, target, and matrix identity where
practical. They MUST validate Incus and image availability, validate KVM for VM profiles, declare intentional
container-versus-VM selection, apply Tiny/Heavy CPU-memory-disk sizing, isolate networks, label owned resources,
capture evidence before destruction, and delete only resources owned by the current run. Unfiltered or ownerless
cleanup on a shared runner is forbidden.

### 8.10 Matrix and CI Policy

1. Every role MUST declare candidate and proven platforms. A target is supported only after all mandatory supported
   profile cells pass on that target.
2. CI matrices MUST be generated from `meta/role-coverage.yml`, use `fail-fast: false`, and avoid uncontrolled
   Cartesian products.
3. Every new role MUST be integrated into the standard workflows.
4. Stable aggregate checks MUST cover lint and sanity, build and install, Tiny, Heavy, Application Acceptance, role
   coverage, evidence, and release validation.
5. Mandatory jobs MUST NOT use `continue-on-error: true`, ignored command failures, or failure suppression.

### 8.11 Secret and Supply-Chain Policy

1. Passwords, tokens, cookies, authorization headers, private keys, activation codes, and recovery material MUST NOT
   appear in logs, reports, screenshots, traces, inventories, artifacts, or evidence.
2. Tests MUST use ephemeral generated credentials, narrowly scoped `no_log`, restrictive file permissions, redaction,
   and a canary test that proves scanner detection before redaction and absence afterward.
3. Release evidence MUST include an SBOM, provenance, GitHub artifact attestations where supported, SHA-256
   checksums, and signatures for the collection artifact, SBOM, and evidence archive. All signatures MUST be verified.
4. Private signing keys MUST NOT be committed. Prefer GitHub OIDC keyless signing.
5. Optional S3-compatible archival MUST use encryption, least-privilege credentials, checksum verification, and the
   documented collection/version/SHA/run prefix. If archival is mandatory for release policy, failure MUST block the
   release.

### 8.12 Fail-Closed Release and Branch Policy

Releases MUST fail closed for a missing or failed mandatory result, mandatory skip, malformed or absent JUnit/Allure,
missing evidence, secret detection, checksum/SBOM/provenance/attestation/signature failure, unsupported production
claim, or tested-SHA mismatch. Release flow is:

```text
feature -> develop PR -> develop -> main PR -> main -> exact-tested-SHA release
```

Do not bypass branch protection, merge failing work, publish from a feature or develop branch, mutate an existing tag,
or add unreviewed changes after release-candidate validation. Publishing MUST install and smoke-test the released
artifact from every configured publication target.

### 8.13 Documentation Policy

Every role's documentation or its authoritative generated coverage entry MUST state purpose, classification,
maturity, candidate and supported platforms, variables, dependencies, security boundaries, Tiny, Heavy, Application
Acceptance, local and CI commands, required secrets, evidence, limitations, external blockers, upgrade behavior, and
backup/restore behavior. Documentation claims MUST match the registry and executed evidence.

<!-- role-quality-governance:end -->

### 8.14 Scenario Quality Gate (Mandatory)

For each new or changed role, and for any newly added scenario:

1. Run every affected supported profile directly with `molecule test -s <scenario>` or the host-native profile
   runner. Run affected experimental light scenarios with `scripts/devtools-molecule.sh <scenario>`.
2. A supported deployment scenario MUST pass converge, idempotence, and verify. Application Acceptance MAY reuse the
   identical Heavy deployment foundation, but its acceptance results MUST remain independently identifiable.
3. `ansible-lint` MUST pass with zero fatal violations for the repository and changed scenario files.
4. You MUST fix lint issues in scenario files (for example var naming or FQCN issues) instead of suppressing them.

## 9. Collection Packaging and `build_ignore`

1. Keep `build_ignore` minimal and justified by real repository artifacts.
2. This repo already ignores common paths (for example `.git`, `.github`, `.molecule`, `.ansible`, `infra`).
3. Recommended additions, when relevant and not already present:
   1. `molecule/` (root scenarios should not ship in release tarballs)
   2. `.venv/`, `.tox/`
   3. `.cache/`, `.pytest_cache/`
   4. `.ansible/`
   5. `dist/`, `build/`

## 10. Role README Standard

Each role `README.md` MUST use these section headers in this order:

1. `## Requirements`
2. `## Variables`
3. `## Dependencies`
4. `## Example Playbook`
5. `## License`
6. `## Author`

Variables section SHOULD point to `defaults/main.yml` and highlight key inputs.

## 11. Definition of Done

Before finalizing, confirm all items below:

1. `pre-commit run --all-files` passes through `ee-wunder-devtools-ubi9`, or failures are explicitly explained.
2. Local collection PR gates pass before using GitHub Actions as verification, whenever the scripts exist and
   the needed runtime is available:
   1. `bash scripts/devtools-changelog-check.sh`
   2. `bash scripts/devtools-ansible-lint.sh`
   3. `bash scripts/devtools-molecule.sh`
   4. `bash scripts/devtools-collection-smoke.sh`
3. If a local gate is skipped, the final response names the missing runtime or concrete blocker, such as no
   Docker/Podman socket or protected Incus requirements.
4. Documentation is updated for changed role interfaces.
5. No CI, workflow, Renovate, or release-automation config changes were made unless requested.
6. Role prechecks are action-scoped and role-scoped:
   1. no cross-role raw var assertions in `assert.yml`
   2. no duplicate copy-paste assert blocks
   3. required foreign inputs mapped in `defaults/main.yml` with role prefix
7. `meta/role-coverage.yml` and all generated coverage/matrix documents are current and pass automated validation.
8. Every role has an explicit maturity, platform, Tiny, Heavy, Application Acceptance, acceptance-surface, blocker,
   dependency, limitation, and deprecation disposition.
9. Every production role has real, green Tiny, Heavy, and Application Acceptance coverage with meaningful verify,
   positive and negative tests, idempotency, JUnit, Allure, and secret-safe evidence.
10. Applicable restart, persistence, reconciliation, backup/restore, and upgrade behavior is proven.
11. Lint, sanity, collection build, clean install, FQCN smoke, evidence schema, canary redaction, SBOM, provenance,
    attestation, signing, signature verification, and exact-SHA release eligibility gates pass.
12. CI and release behavior remains fail-closed, and documentation contains no stronger support claim than executed
    evidence proves.


### Protected SINGLE controller host exception (2026-10-06)

The owner-authorized exception to the Devtools execution boundary applies only
in the protected Exact-Revision SINGLE workflow. Its immutable controller may
use host Python for tuple-bound materialization and regeneration, host/cgroup
resource admission, root-owned `/run` bootstrap and loopback supervision, and
the authenticated receipt lifecycle. Controller and imported runtime assets
must remain bound to the protected workflow/base Git blobs; candidate code is
review data and must never be imported or executed.

These narrowly admitted controller checks are not generic host acceptance
evidence or native review acceptance. Lint, test, build, package and unrelated
validators remain in pinned Devtools. The deterministic receipt collector must
start before `drop-sudo`, with the original runner UID/GID, read-only inputs and
no network or service-socket mount. Its existing protected supervisor may
publish only the successful collector's bounded output. No sudo/Docker access
is restored after privilege removal. This exception grants no extra inference,
request, retry, replay, funding or promotion authority; Devtools still never
runs a model invocation.

<!-- LIT at-most-once review funding: start -->

## At-most-once review funding

The owner-authorized 2026-10-06 amendment requires a durable, exact-head
reservation before the one review-request POST. Enabled pilot requests confirm
the protected Git CAS claim before the effect; disabled/default and non-pilot
requests confirm the durable UNCERTAIN comment reservation without CAS.
Reservation proves consumption only, never delivery, review quality, or acceptance.
After an unknown POST outcome, observe review delivery only through GET reads;
do not repeat the same-head AI request. Base drift, a new run, or missing pending
state never restores that consumed opportunity. Every completed same-head review
from the trusted Copilot bot consumes the funding opportunity, including failed,
quota-blocked, changes-requested, and dismissed reviews, regardless of body or
inline content. The separate policy/evidence gate must still reject unusable
content and unresolved findings. This amendment grants no bypass or weaker
platform, protected-source, actor, Required-Workflow, or merge authority.

<!-- LIT at-most-once review funding: end -->
