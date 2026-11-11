# G06 Main acquisition courier

The protected Supplementary Main build supplies its own short-lived, read-only job
credential to the existing Root generation acquisition on ciwkr01. The public RSA
binding in `.lit/g06-courier.json` belongs to one fresh Root-owned tmpfs key. The
courier is restricted to the reviewed transition from Main `90e7216b` and attempt
one. The collection package excludes this CI directory and `.lit`.

The hosted job waits at `ansible-collection-release-prepare`. Before approving
that exact job, the operator verifies the new Main/candidate, accepted Validation
callee, runner-group policy, Source platform and the fresh Root key metadata.
Preparation and encryption run in pinned Devtools with only the job's `contents:
read` and `actions: read` credential. The temporary artifact contains an encrypted
handoff and public run bindings. Plaintext credentials and private keys stay out
of logs, repository files and retained evidence.

The courier holds its original 900-second window. Root requires at least 690
seconds remaining before accepting the handoff and uses the normal acquisition
with a 600-second limit and a 90-second reserve. The operator must verify the
native artifact/run/job metadata, deliver the bounded ciphertext privately,
complete acquisition, delete the exact transport artifact and read back its
absence. Root erasure also requires the courier job to have completed and its
credential to return HTTP 401. Retain only metadata receipts. Partial or ambiguous
operations remain held for investigation; they never authorize another envelope
or an apparent cleanup success.

Heavy and Application Acceptance use the prepared physical Runner01 and same-host
Incus VMs. Their own job-scoped API/OIDC credentials are independent of the
courier. Each operating run requires fresh, valid Root generation bindings and
its explicit custody, resource and cleanup checks.
