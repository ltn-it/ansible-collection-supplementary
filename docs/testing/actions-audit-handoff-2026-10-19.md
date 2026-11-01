# Actions audit implementation boundary, 19 October 2026

This change addresses LTN-150, LTN-344 and LTN-360. It is local implementation
and deterministic validation, pending ordinary delivery and native acceptance.
It does not complete a release or change repository protection.

## Bound baseline and ownership

- Repository: `lightning-it/ansible-collection-supplementary`, ID `1103407173`.
- Develop: `c5fb4cd319aa4d55516a431bbdf946d383afe0c9`.
- Main: `7629452aaed2ce00cbd3809114915337613deaed`.
- Both trees: `60353b488991dfb66e057a66b047e981d20720ce`.
- Audit: 19 October 2026, LTN-150 comment 16062, LTN-344 comment 16061,
  LTN-360 comment 16060. Mutable sources were reread before implementation.
- The existing 42-path candidate owned by chat
  `01a15413-3712-7c31-9d96-3614a9a082a8` remains independent. Its controller
  retirement, release preparation, publication, archive and back-sync changes
  are preserved. This patch changes none of those files or that candidate.
- LTN-386 remains with its image owner. Source3 pins, review reservations,
  consumed operation refs, native history and remaining budgets are unchanged.

## Local changes and failure semantics

Scorecard adopts the canonical Shared Main
`37ab599e2e338a9f7e594f5c919dcd889c892746` timeouts: scan 60 minutes and SARIF
upload 10 minutes. The resulting entire YAML is byte-identical to that source.
No source edit or synchronization is needed. AGENTS section 1.1 permits reviewed
local adoption; its specialized synchronizer and the source quality-policy
renderer must preserve other local workflow behavior. The foreign ModuLix
validator timeout observation stays separate in LTN-150.

Collection CI adds a 10-minute, read-only `release-admission` job before either
release evidence Environment and before OIDC/signing/archive credentials. It
requires successful classification, quality matrix and every mandatory
aggregate. Same-run artifact download, candidate/evidence checksums, existing
release-grade evidence validation and repository/SHA/run/attempt equality must
all pass before its `admitted` output can grant Environment access.

| Observation | Admission behavior |
| --- | --- |
| Failed, cancelled or skipped mandatory aggregate | Failure report, no Environment; final Release Validation fails |
| Missing, queued or pending result | Pending report, no admission; never converted to success |
| Wrong repository, commit, producer run or attempt | Stale report, no admission |
| Valid not-applicable profile cells | Existing aggregate validates `required=false` and skipped cells, then succeeds |
| Successful complete aggregates and exact valid artifacts | Admission succeeds; normal Environment policy still applies |

The `needs` graph uses this run's terminal jobs; no external check-name lookup,
poll, dispatch, retry or synthesized producer success is introduced. The
existing runtime failure artifacts and Release Security's failure upload remain.
The new admission report is also retained with run/attempt identity. Final
Release Validation keeps `always()` and explicitly requires admission success.
A failed checksum/validator leaves the preceding phase recorded, while the
failed step/job prevents admission; a phase report alone is not acceptance.

## LTN-344 retirement evidence and retained controllers

Nine aliases were guarded by `github.event_name == 'workflow_call'`, but
Collection CI declares only PR, push and manual dispatch. No such invocation
can reach them. All current remote branch workflow/script/metadata files were
searched: their alias references are definitions only, with no caller or
dependent `needs`. Current Main/Develop classic requirements and all effective
rules contain none of their contexts. The canonical specialized renderer only
replaces the marked `lint-sanity` quality-policy step and preserves the edited
local jobs outside that marked lint step. A second rendering is idempotent.
The existing local lint-step block differs from current Source; this unrelated
baseline drift is retained rather than adopted as part of the audit fix.

Removed IDs: `legacy-lint`, `legacy-build`, `legacy-molecule`,
`keycloak-legacy-lint-sanity`, `keycloak-legacy-tiny`, `keycloak-legacy-heavy`,
`keycloak-legacy-acceptance`, `keycloak-legacy-evidence`, and
`keycloak-legacy-release-validation`. Their real quality aggregates remain.
The unreachable `nightly-develop` branch of both matching Tiny predicates is
removed; the sole manual option remains `manual-main`.

The eleven disabled historical controllers are not deleted in this patch.
The separate owner's retirement candidate already changes seven of them;
remaining reusable and release helper/caller contracts require that coordinated
replacement. Open foreign review-controller PRs 1180/1181/1182 and Shared sync
PR1151 are preserved. Registrations without a current file (`release.yml`,
`keycloak.yml`) and all retained runs remain historical inventory. No registry
disable/delete, operations-ref cleanup or flag change is part of this patch.

## Exact protected-change plan: prepared, not executed

Current organization rules `25323832` (Develop) and `25357327` (Main) both have
`enforcement=evaluate`, repository selector `[1103407173]`, no bypass actors,
and select `.github` repository `1112629689`, workflow
`.github/workflows/change-control-required.yml` at
`bb1a5df9f54c5f98547048297e7e367cc382543e`, ref `refs/heads/main`.
Effective Main rules therefore contain no required Common workflow. Classic
Main is strict and requires only `Collection / Fast` and
`Collection / Release Evidence`, both App `15368`; Develop requires only Fast.
Neither requirement represents final Main promotion or final release acceptance.

The selected Common source already declares native normal approval and a final
`Current revision review` job, but Evaluate does not enforce either. A prior
green standalone `Main promotion merge gate` is not proof that making its old
name mandatory is correct. The current Management POC contract also explicitly
has `mandatory_ai_review=false`, `historical_evidence_gate=false` and
`automatic_promotion=false`; an activation must respect or explicitly resolve
that source contract through its owner.

The smallest protected delta, after qualification and separate authorization,
is to update existing Main organization rule `25357327` through its existing
Management owner. Develop rule `25323832` remains Evaluate unless separately
commissioned. Preserve repository/ref selectors, workflow repository/path,
`do_not_enforce_on_create=false`, bypass list and every other rule/protection.
Change Evaluate to Active only for an independently accepted immutable Common
source that supplies the required exact-head review, native approval and final
promotion result. Retain `bb1a5df...` only if it actually meets that qualification;
otherwise first deliver the approved source selection in the same reviewed
Management plan. Do not follow mutable Main or copy another repository's pin.
No extra historical check name is proposed as a required context.

Before that protected mutation, the owner must bind the exact new source SHA,
full rule bodies, protected tips, existing approval Environment, plan hash and
scope. Prove missing, failed, pending, stale and unapproved promotion rejection,
successful exact-tuple promotion, valid exemptions and at-most-once review
funding. Preserve original rules for rollback and read back full rules and
effective Main/Develop protections after the separately approved native apply.
No activation is authorized by this audit fix; this plan remains blocked on
that source qualification and explicit protected-change authorization.

## Delivery, acceptance and rollback

Deliver this focused change through an ordinary PR to Develop. PR creation
triggers automatic PR workflows even in Draft, so publication must wait for the
human's concrete PR-CI decision. Do not use a skip marker, temporary disable or
other CI suppression. The complete patch, PR body and local results are secured
before requesting that decision.

Local deterministic checks prove code behavior only. Native Main enforcement,
the qualified LTN-386 image handoff, current Application/Runtime acceptance,
release signatures/provenance/archive and a new Galaxy version with verified
download and fresh explicit installation remain open. Nexus runtime/cutover
stays deferred under LTN-371/LTN-118. No checklist is satisfied by local code alone.

Rollback is an ordinary reviewed revert of this focused patch, preserving the
existing controller candidate, tags, native runs and consumed operations. A
future policy rollback is a separate authorized Management operation using its
saved exact pre-change rule bodies. This patch requires no settings rollback.
