# Repository metadata and changelog fragments

The root `.lit/` namespace is reserved for repository governance and delivery
metadata: workflow-control policy, ancestry, quality contracts, source bindings,
and audit or release evidence. Its files, including new or nested control
metadata, are not collection runtime modules, roles, templates, or assets. Keep
runtime content under its normal collection paths; do not load runtime content
from `.lit/`.

The changelog policy treats this reserved namespace like `.github/`: a change
limited to repository metadata does not need an end-user release-note fragment.
The rule is independent of branch names, PR authors, and skip labels. A mixed
change that also modifies user-visible roles, plugins, defaults, or other
collection behavior still needs a normal fragment under `changelogs/fragments/`.
Names such as `.literal/` or `roles/example/.lit/` are outside the reserved root
namespace.

This is release-note classification, not validation or authorization. Existing
JSON parsing, schema, quality, security, provenance, and protected governance
checks remain independent and required. Malformed JSON does not become valid
because its path is metadata. The changelog checker does not define a second
workflow-control schema or authorize changes to policy, settings, or releases.
Generated changelog files retain their existing release and provenance guards.

The policy lives in `scripts/devtools-changelog-check.sh`; both the standalone
changelog workflow and the pre-commit hook used by Collection CI call that same
script. Behavioral tests exercise real Bash and Git diffs; independent fragment
lint and JSON/schema checks retain their own responsibilities.

This repository adopts the canonical `shared-assets-lit/ansible-collection/base/`
namespace rule while retaining its local release, baseline-import, and provenance
checks. The collection package excludes `.lit/` through `galaxy.yml` build_ignore.
