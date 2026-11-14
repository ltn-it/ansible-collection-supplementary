# Audit evidence

Every supported Heavy and Application Acceptance matrix cell contributes a
structured, secret-safe evidence package. Failed runs contribute evidence when
the runner can still capture it.

```text
artifacts/evidence/
├── manifest.json
├── environment.json
├── role-coverage.yml
├── source/
├── collection/
├── matrix/
├── junit/
├── allure-results/
├── allure-report/
├── logs/
├── screenshots/
├── playwright-traces/
├── configuration/
├── dependencies/
├── security/
└── checksums/SHA256SUMS
```

Evidence records repository, branch/tag, exact commit, collection version,
role, profile, scenario, target, runner, workflow/run/attempt, actor, timestamps,
tool/application versions, test totals, blockers, support classification,
checksums, and automatically calculated release eligibility.

Dependency evidence records controller Ansible, Molecule, Python, pip package,
and installed collection inventories; the resolved Incus base image; the
host-native execution-environment disposition; scenario dependency inputs; and
in-target container image digests or immutable image IDs. Application
Acceptance also records the exact Playwright version, stable Chrome channel,
browser version and executable SHA-256, plus the target operating-system
package inventory installed for that browser. Binary packages are tied to the
exact distro and source-package identity so vulnerability matching does not
lose Ubuntu/RHEL advisory context. The Chromium component carries its exact
digest and the conservative NVD Google Chrome CPE used for Chromium security
advisory matching. These cell-bound runtime records are added to the CycloneDX
SBOM. Release validation rejects a missing, empty,
unavailable, unbound, or mutable-only dependency inventory.

The manifest contract is defined by
[`evidence-manifest.schema.json`](evidence-manifest.schema.json). Validation is
not limited to trusting the manifest and its checksum list: the validator
applies the structural contract, reparses every referenced JUnit and Allure
result, re-derives result status, totals, testcase identity, role coverage, and
matrix status, and revalidates the security documents and embedded role
coverage registry.

Allowed result states are `passed`, `failed`,
`skipped-with-approved-justification`, `not-applicable`,
`infrastructure-error`, and the three `blocked-external-*` states. A mandatory
skip is not a pass.

Use the generic assembler and validator:

```bash
python3 scripts/quality_evidence.py assemble
python3 scripts/quality_evidence.py validate
```

## Physical finalization survives reaggregation

A preliminary Root cell is diagnostic evidence (`root_finalization: pending`),
not final quality acceptance. Copying its reports, expanding a nested transport,
mixing reports with ordinary inputs, or assembling an existing output again
cannot remove this barrier. Candidate inputs likewise cannot become ordinary
final evidence by reaggregation. Ordinary offline business evidence remains
supported.

Protected-main aggregation verifies the exact Heavy/keycloak-heavy/ubuntu-24.04
and Application Acceptance/keycloak-application-acceptance/ubuntu-24.04 pair.
It uses the existing pinned Root public key, signed final-quality domain,
independent native job/check/artifact records and complete provider ZIP/member
byte comparison. The verified importer, assembler and validator run in one
process. Its opaque verification result is bound to exact file inventories;
constructing an object or supplying a path grants no acceptance.

The final manifest retains `root_final_quality_inputs`: relative references to
original preliminary cell trees and canonical signed envelopes below
`root-final-inputs/<artifact-id>/`. These raw cell files are preserved unchanged,
including their own manifests/checksums, JUnit and Allure bytes. References and
digests locate evidence; they are not cached authorization. A later process
must independently repeat the same native and ZIP verification using its
normal ephemeral `GITHUB_TOKEN`, the workflow-pinned
`G06_VALIDATION_CONTROLLER_SHA` (reusable callee B, not action A), expected
source commit and original CI run (`CI_RUN_ID`, otherwise `GITHUB_RUN_ID`).
Missing native access or expected controller/run information holds physical
acceptance. Publication uses its existing authenticated original `CI_RUN_ID`.

The public final-evidence JWS is distinguished from a credential only after
this complete verification, at its exact envelope path and bytes. Only that
signature value is masked for scanning; every receipt field and all other
content still receive the ordinary secret scanner. Unverified/fake JWTs and
modified envelopes are never exempt. All retained copies count toward the
unchanged 256 MiB/file, 512 MiB total and 10,000-file limits; overflow holds.

Each fresh two-cell verification needs six native metadata GETs, two API ZIP
redirect GETs and two signed blob downloads. The same-process path avoids a
second verification round; each independent validation/reaggregation repeats
it. Existing 30-second request and 300-second ZIP download ceilings remain, but a
fixed 240-second whole-verification phase is stricter. Native reads, both ZIPs,
local verification and same-process aggregation share that monotonic deadline;
nesting and opaque proof reuse cannot reset it. Request timeouts are clamped to
the remaining phase. Every affected workflow starts its existing job clock
before checkout/setup and leaves a 90-second safety reserve; verification uses
the stricter remaining clock. Exhaustion explicitly holds, without increasing
job timeouts or dropping checks. A blocked network read can take its bounded
remaining request timeout to return; native whole-job qualification is still
required before promotion.

The representative two-cell fixture uses 16 MiB of deterministic public capture
and 1,000 additional real files per cell. Real signatures, tree inventories,
ZIP bytes and aggregation/validation execute locally; HTTP alone is modeled.
It measures setup, verification and request counts without claiming native
provider latency. Actual operator-configured Root capture limits and native
whole-job timing remain required production inputs; larger evidence still
obeys the unchanged byte/file caps and phase budget.

## Test identity and role proof

Every final JUnit document identifies the tested commit with an exact lowercase
40- or 64-character hexadecimal SHA. Its suite identity also includes profile,
scenario, target, workflow attempt, and role declarations.

A single-role suite may apply its suite role to its testcases. A shared scenario
must instead assign exactly one declared role to every testcase with a `role`
attribute or testcase property. Every required role must have at least one
meaningful testcase of its own. One testcase is never cloned into several role
results.

Native pytest Allure is accepted only when exactly one result matches each
JUnit testcase name and class identity, status, role, profile, scenario, target,
workflow attempt, and commit. A native Allure result cannot be reused. Pytest
producers must independently label each result with its single evidence role;
the trusted recorder adds the workflow-owned matrix and commit labels but does
not invent or replace role proof.

## Release inputs

Release mode requires the embedded `meta/role-coverage.yml` registry and the
complete, nonempty production matrix derived from it. A missing registry, an
unregistered result, or a filtered release matrix is ineligible.

The trusted workflow can bind prerequisite job conclusions through
`QUALITY_EVIDENCE_PREREQUISITES_JSON` (the
`QUALITY_EVIDENCE_PREREQUISITES` alias is also accepted). When supplied, it is
a JSON object with exactly these keys, all set to `"success"`: `lint`, `build`,
`coverage`, `tiny`, `heavy`, `acceptance`, `cleanup`, and `destroy`. Missing,
unknown, malformed, or non-success entries become blockers and the values are
recorded in `manifest.json`. Omitting the optional input leaves
`prerequisites` empty for local callers.

The assembler plants a synthetic secret, proves the scanner detects it, applies
redaction, and proves it is absent. Final text, binary, and archive inputs are
scanned. Secret-like material that cannot be safely redacted blocks publication.
Checksums cover every final evidence file except the checksum list itself.

Redaction and scanning cover ordinary assignments, structured JSON
name/value and header/value objects, authorization and cookie headers, Basic
and Bearer credentials, JWTs, common API-key formats, URL credentials, XML
secret properties, and private keys. Structured labels are preserved while
their values are replaced.

Evidence processing is bounded: at most 10,000 files and 512 MiB of stored
evidence are scanned; an individual file is limited to 256 MiB; archives are
limited to 4,096 members, 256 MiB expanded content, 64 MiB per member, and a
200:1 compression ratio. An oversized or otherwise unscannable file or
archive blocks evidence instead of being copied through unredacted.

Release mode additionally requires a CycloneDX SBOM, vulnerability result,
provenance, and secret-scan summary. GitHub artifact attestations and keyless
Cosign bundles are produced and verified for the collection, SBOM, and evidence
archive in the protected main-only release-evidence environment. Pull-request
code cannot request OIDC tokens, attestation writes, or archive credentials.

Candidate mode records whether the candidate-target execution passed but always
sets `release_eligible` to false. Candidate evidence can support a reviewed
registry promotion decision; it cannot satisfy the supported release matrix.

Those four JSON files are validated semantically. Provenance must bind the exact
commit, workflow, and exact `<namespace>-<name>-<version>.tar.gz` filename to a
SHA-256 candidate digest. The CycloneDX root component must then match those
Galaxy coordinates and that digest. Grype must identify itself and prove it
scanned that candidate-bound `sbom.cdx.json`, contain a match array, and have no
High or Critical findings. The secret summary must identify its scanner/plugins
and contain a well-formed results mapping with no findings. Empty, unrelated,
or wrong-source objects are not evidence.

GitHub Actions artifacts provide immediate retention. Optional encrypted
S3-compatible archival is documented in [`RELEASE.md`](../../RELEASE.md) and
uses the collection version, commit, and run in its object prefix. The base
manifest records `pending-release-security` on a protected-main push; it never
predicts archival success. A separately signed release-security receipt records
`verified` only after upload and exact download checksum verification. The
archive contains candidate, raw evidence, final authenticated checksums,
signatures, and attestation material; the receipt and its verification material
are retained alongside it. Variables and protected-environment credentials are
listed in the release guide. The reviewed `.lit/repository.yml` policy alone
decides whether a missing archive blocks release.
