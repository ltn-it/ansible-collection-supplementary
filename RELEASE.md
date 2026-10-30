# Release Model

This Ansible collection uses a reviewed, exact-SHA, fail-closed release flow.

## Repository classification

- Collection: `lit.supplementary`
- Repository type: `ansible_collection`
- Stable branch: `main`
- Integration branch: `develop`
- Artifact: Ansible collection tarball
- Publication targets: GitHub Release and Ansible Galaxy
- Evidence: mandatory for supported profiles and releases
- Long-term S3-compatible archival: optional unless repository policy marks it
  mandatory

## Branch flow

```text
feature
-> pull request to develop
-> integration validation on develop
-> reviewed develop-to-main code convergence
-> reviewed main-to-develop ancestry convergence
-> protected-main tooling prepares exact Develop release data
-> release/vX.Y.Z pull request to develop
-> required checks on the prepared Develop revision
-> reviewed develop-to-main release promotion
-> validation and publication of the exact main SHA
-> published-release back-sync pull request to develop
```

Do not direct-push release commits, bypass protection, use an administrator
override, or publish from a feature/develop branch. A release-generated change
must be back-synced before the next promotion.

Every merge into `main`, including a develop-to-main promotion that does not
yet publish a release, must become an ancestor of `develop` through a reviewed
back-sync pull request before another promotion is opened.
The back-sync must preserve the current `develop` tree and record the current
protected `main` SHA as its second parent; a stale parent or changed source tree
must fail closed.

This is the normal two-stage release route. The evidence-bound Security route
retains its separate direct-to-`main` release preparation. Normal preparation
uses protected Main tooling with the exact bound Develop metadata and fragments;
generator code, plugins, configuration, and role-documentation inventory must
converge through ordinary Main review before release credentials are used.

## Validation lanes

Collection source pull requests require the stable `Collection / Fast` aggregate
for the Fast Lane. It covers lint/sanity, build/install, role coverage, and only
the registry-selected Tiny profiles. A Keycloak-only change therefore does not
start Satellite validation.

Heavy and Application Acceptance validation execute centrally and asynchronously
against the exact immutable release identity. They do not block the source-repository
merge or the initial candidate publication. Repository settings are managed
through `github-management-lit`, not ad hoc workflow or API changes.

`Collection / Release Evidence` remains the exact-main compatibility and
evidence gate where the current workflow requires it. It does not execute Heavy
or Application Acceptance validation in the Collection source repository.

Until the Nexus Collection registry is available, release publication continues
directly to Galaxy. The central transition workflow validates repository,
commit, version, artifact name, and SHA-256 digest and prints the future Galaxy
promotion command; it performs no Heavy or Application Acceptance execution and
does not publish to Galaxy a second time. Cross-repository dispatch uses a short-lived
Release Automation GitHub App token, not a long-lived personal access token.

A staged candidate or a transition no-op is not Heavy or Application Acceptance
evidence. Final acceptance still requires the applicable mandatory profiles and
the publication and post-release checks below.

## Release eligibility

Eligibility is calculated from actual registry-derived matrix results and
evidence. It fails closed for any mandatory failure or skip, lint/sanity/build
failure, unsupported production claim, missing or malformed JUnit/Allure,
missing evidence, secret detection, checksum failure, missing SBOM/provenance,
attestation or signing failure, signature verification failure, archival failure
when mandatory, or tested/released SHA mismatch.

An edited variable or hand-written status file cannot make a release eligible.

## Trusted release-preparation changes

Release-preparation pull requests created by the configured GitHub App are
accepted only when the required trusted verifier binds the pull request's exact
head SHA to a successful release-preparation workflow run and validates the
generated receipt and release diff. This narrowly scoped machine-identity
control is not a generic review exception: human-authored changes, an
unverified bot commit, or any SHA mismatch fail closed and still require the
normal protected-branch review and checks.

## Version and changelog

`galaxy.yml` is the version source of truth. Normal implementation pull requests
add fragments under `changelogs/fragments/` and do not edit generated changelog
files. Release branches run `antsibull-changelog`, update `CHANGELOG.rst`,
`changelogs/changelog.yaml`, and `galaxy.yml`. Normal release preparation opens
its reviewed PR to `develop`; the subsequent ordinary promotion supplies the
exact release-ready Main revision. Security preparation retains its separately
governed Main target.

Choose semantic versioning from actual compatibility impact. Do not reuse or
move a tag. Release preparation maps `breaking_changes`, `major_changes`, and
`removed_features` to major; `deprecated_features` and `minor_changes` to
minor; and `bugfixes` and `security_fixes` to patch. It rejects unstable,
skipped, or manually overridden versions and requires the exact next stable
version. Release PRs use merge commits only; squash and rebase merges are not
valid release inputs.

Before dispatch, compare both protected branches with the highest stable version
actually published on GitHub and Galaxy. Resolve an outdated baseline through
the existing reviewed convergence path; do not override the version parser or
hand-edit generated changelogs to work around it.

Before consuming the fragments, release preparation commits
`changelogs/release-preparation.json`. The receipt binds the current and next
versions, semantic impact, every fragment SHA-256, repository identity, release
bot, and exact workflow run. A normal schema-3 receipt keeps the Develop content
base (`base_sha` and `content_base.sha`) separate from the protected Main tooling
source (`workflow.source_sha`); one source identity never substitutes for the
other. Publication first recomputes the version from the receipt-bound fragments
in the content base,
requires the reviewed release commit to have that single parent and the exact
bot author/committer identity, and verifies that the recorded protected-main
preparation run completed successfully. Any mismatch stops publication before
tag, release, or Galaxy mutation.

Release preparation uses the existing Release Automation GitHub App installation
token, scoped to this repository, to create the reviewed release branch and pull
request. Publication uses its separate protected credentials. A generic
repository `GITHUB_TOKEN` cannot provide
stage separation because every workflow is attributed to GitHub Actions App
`15368`. Governance blocks all `v*` creation except an exact, reviewed dedicated
release-tag GitHub App installation. The publish job mints a repository-scoped
installation token, verifies the configured App ID, installation ID, owner, and
sole repository before using that token only for annotated-tag creation. GitHub
Release assets continue to use the separate environment-gated workflow token.
The required App, installation, variables, private-key secret, ruleset bypass,
and environment controls must exist in live governance before publication; an
unapplied or incomplete configuration is an explicit release blocker.

## Release validation and supply chain

For the exact main SHA, the trusted release workflow must:

1. require all stable aggregate checks and a release-eligible evidence manifest;
2. build the collection and inspect its `MANIFEST.json`;
3. install it into a clean collection path and run an FQCN smoke test;
4. validate the candidate's exact `meta/source-dependencies.yml` and create a
   commit-bound CycloneDX SBOM for every shipped image, collection, licensed
   product disposition, and executed test dependency;
5. create provenance and GitHub artifact attestations where supported;
6. create and keylessly authenticate SHA-256 checksum manifests;
7. keylessly sign the collection, SBOM, and evidence archive with GitHub OIDC;
8. verify every signature and checksum before publication;
9. archive evidence to the configured S3-compatible store when enabled; and
10. publish the exact verified artifacts without rebuilding them.

Pull-request-editable jobs can create only unsigned base evidence. OIDC,
attestation writes, and archive credentials exist only in the protected,
main-only `ansible-collection-release-evidence` environment. Publication uses
the separate `ansible-collections` environment, and release branch/back-sync
automation uses `ansible-collection-release-prepare`. Private signing keys and
publishing credentials are never committed or exposed to self-hosted test jobs.

## Required GitHub Release attachments

- collection tarball
- `SHA256SUMS`
- CycloneDX SBOM
- provenance
- signature and attestation bundles
- release evidence in JSON and Markdown
- signed release-security and post-publication verification receipts
- complete long-term release-evidence bundle and its checksum
- `role-coverage.yml`
- executed matrix summary

## Publication and post-release verification

When `.lit/repository.yml` enables Galaxy publishing, missing credentials or a
Galaxy failure makes the release incomplete. After publication, download the
GitHub Release artifact, verify its digest/signature, install the Galaxy version
in a clean path, and run the FQCN smoke test again. Only then is the release
complete. The workflow attaches a deterministic, keylessly signed
`post-release-verification.json` only after GitHub download/install smoke,
configured Galaxy digest/install smoke, and release back-sync dispatch have all
succeeded. A retry verifies an existing receipt byte-for-byte and never
overwrites it.

## Evidence retention

GitHub Actions artifacts provide immediate evidence. Optional S3-compatible
archival supports AWS S3, MinIO, and compatible endpoints under:

```text
ansible-collection-supplementary/<version>/<commit-sha>/<workflow-run-id>/
```

Use encryption, versioning, Object Lock/WORM where available, retention policy,
least-privilege credentials, and upload checksum verification. Do not put
secrets in object metadata. Configure:

- repository variable `QUALITY_EVIDENCE_S3_BUCKET`;
- optional repository variable `QUALITY_EVIDENCE_S3_ENDPOINT` for MinIO or
  another compatible endpoint;
- protected `ansible-collection-release-evidence` environment secrets
  `QUALITY_EVIDENCE_AWS_ACCESS_KEY_ID` and
  `QUALITY_EVIDENCE_AWS_SECRET_ACCESS_KEY`; and
- optional protected-environment secret
  `QUALITY_EVIDENCE_AWS_SESSION_TOKEN`.

Do not create repository-scoped copies of the AWS credentials. A custom endpoint
must be a credential-free HTTPS URL. The workflow uploads the complete candidate,
raw evidence, dependency/security inventory, checksum signature, and attestation
set as one bundle with AES256 server-side encryption. It downloads and verifies
that exact object, then uploads and verifies the separately signed final archive
receipt under the same prefix. Bucket versioning, retention, and Object Lock/WORM
are storage-side controls. Whether archival is mandatory comes only from the reviewed
`.lit/repository.yml:enterprise_role_quality.long_term_archive_required` policy;
it is not a mutable workflow-dispatch input or repository variable.

The release-preparation data transport lives in
`scripts/normal_release_environment.sh` so the workflow's shell step stays below
GitHub's 21,000-character limit. The workflow loads this helper from the exact
protected Main Git object before executing it; a candidate checkout cannot supply
the helper. Its private Devtools context still excludes App and GitHub credentials.
Delivering this helper to Develop does not grant Main or release acceptance.
