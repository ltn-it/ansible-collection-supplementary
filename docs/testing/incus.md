# Incus test environments

Supported profile scenarios run host-native against Incus. The shared lifecycle
under `molecule/shared/incus/` creates and destroys exact-owned instances. Local
mode also creates and destroys one managed bridge per matrix cell; explicit TLS
mode attaches to a Root-precreated bridge and defers its cleanup to Root.

## Identity and ownership

CI instance names incorporate scenario, workflow run, attempt, and target. The
bridge name is deterministic for the complete exact-owner value (`lit` plus the
first 12 hexadecimal characters of its SHA-256 digest) and remains within the
Linux interface-name limit. Every instance and bridge carries the generic
`user.lit-molecule-owner` label plus repository, run, attempt, scenario, and
target labels. A compatibility owner label may also be written for a specialized
scenario.

Creation refuses an existing instance or bridge owned by another run. Labels are
part of the `incus init` and local `incus network create` requests, so there is no
unowned interval after resource creation. Each instance receives a local `eth0`
attachment to the exact-owned bridge before it can start. Local reruns may reconcile
only resources with both expected owner labels. Never use unfiltered stale
cleanup on a shared runner.

When no owner is exported for a local Molecule invocation, the generated run ID
is atomically persisted in a private, context-hashed file below
`$MOLECULE_EPHEMERAL_DIRECTORY/lit-incus-lifecycle/`. A later standalone
`molecule destroy` with the same scenario and instance name reuses that ID. The
file rejects symlinks, unexpected content, foreign ownership, and permissive
modes; it is removed only after destroy proves that no exact-owned resource
remains. Protected CI always supplies an explicit owner and does not use this
fallback.

The bridge uses Incus-managed IPv4 DHCP and NAT, disables IPv6, and lets Incus
select a non-conflicting subnet. The former guest-side `10.248.82.0/24` setup ran
after instance start and was not safe for concurrent cells; it is retired. Tests
must not replace routes or `/etc/resolv.conf` manually.

### Host firewall interoperability

Incus and another nftables controller can both accept a packet, but a later
firewall chain can still reject it. Incus documents that this can break DHCP,
DNS, and external access and recommends placing the bridge in firewalld's
`trusted` zone. See [How to configure your firewall](https://linuxcontainers.org/incus/docs/main/howto/network_bridge_firewalld/).

The test lifecycle applies that guidance without changing permanent host state.
When `firewalld.service` is active, it disables Incus filtering only for the
exact-owned bridge, records the selected controller and zone on that bridge,
refuses a conflicting pre-existing interface binding, and adds the exact bridge
to an existing zone at runtime. Destroy verifies the recorded owner and zone,
removes the runtime binding before attempting network deletion, and records the
result. It never passes `--permanent`, reloads firewalld, or changes `incusbr0`.
Hosts without active firewalld continue to use Incus filtering unchanged.

The stock `trusted` zone permits guests on that one bridge to reach host
services, not only DHCP and DNS. This is an explicit tradeoff in firewalld's
documented bridge integration. Its exposure is bounded to a collision-resistant
per-run interface containing only declared exact-owned instances, protected
runner execution, and the runtime from create through destroy. Operators with a
pre-existing restrictive zone and forwarding policy can select it with
`MOLECULE_INCUS_FIREWALLD_ZONE`; the lifecycle validates that the zone already
exists and does not create persistent policy. The selected zone must allow DHCP
and DNS to the host and outbound forwarding/NAT. An interrupted run can leave a
runtime-only binding until firewalld reload or host reboot; rerunning destroy
with the same exact owner removes it deterministically.

After instance start, create waits for an Incus-managed IPv4 lease and then
proves a guest default route and IPv4 DNS resolution. `MOLECULE_INCUS_DNS_PROBE`
can select an approved DNS probe name. A host firewall that is neither inactive
nor covered by the firewalld integration fails these readiness checks instead of
surfacing later as an empty apt-cache error.

## Preflight

Before create, validate:

- Incus client/daemon availability and the requested image;
- available disk and memory against profile limits;
- `/dev/kvm` when `type: vm` is selected;
- target architecture and intentional container-versus-VM choice; and
- required outbound package/image access.

If firewalld is active, the runner identity also needs non-interactive privilege
for runtime-only `firewall-cmd` interface binding and removal. Do not grant
permission for permanent zone or policy changes to the test workflow.

Tiny uses the smallest sufficient container. Heavy/Acceptance use a VM only
when kernel behavior, full systemd fidelity, nested virtualization, or operating
system fidelity requires one. CPU, memory, and disk limits are explicit in the
scenario matrix.

## Explicit remote TLS cells

The existing local transport remains the default. The new `tls` transport is a
client for an independently admitted cell; it does not issue certificates,
verify native-job admission, select a custodian, reserve host resources, or
authorize a rollout. Live restricted-certificate access, VM execution and the
complete protected launcher remain mandatory integration qualifications.

The root launcher supplies these nonsecret routing values only after it has
verified admission and bound the cell:

| Variable | Required TLS value |
| --- | --- |
| `MOLECULE_INCUS_TRANSPORT` | `tls` |
| `INCUS_CONF` | `/incus` |
| `MOLECULE_INCUS_REMOTE` | `quality` |
| `MOLECULE_INCUS_PROJECT` | The lease's exact isolated project |

All six existing Incus-backed scenario inventories explicitly map the last two
values to `ansible_incus_remote` and `ansible_incus_project`. This is necessary
because `community.general.incus` explicitly defaults to `local:`, project
`default`, even when the CLI configuration has another default remote. Its
existing local/default fallbacks are preserved. TLS instance names must be
DNS-label safe so the connection plugin cannot truncate a dotted identifier to
a different instance. The complete existing matrix, VM choice, guest preparation,
converge, idempotence, verification, capture and destroy stay intact.

The shared scenarios retain `security.idmap.isolated=true` for their container
baseline. The lifecycle applies this container-only option only to container
targets, including the legacy default type. A runtime-selected VM has its own
kernel and receives no UID-map option; the other requested configuration still
reaches Incus unchanged. The typed command regression executes the production
Ansible task with an inert CLI recorder; it does not claim a live VM result.

The fixed private context contains exactly `binding.json`, `config.yml`,
`client.crt`, `client.key` and `servercerts/quality.crt`. Directories are owned by
the cell UID with mode0700; files are owned, singly linked, ordinary0600 files.
The separately typed legacy binding uses integer schema2 and the previous
repository/run/attempt/server/project/expiry fields, the [required runtime
projection](#tls2-runtime-projection), and a compact `admission` JWS. The root
launcher must cryptographically verify that JWS, its canonical binding digest
and all context-file digests before candidate acquisition or cell startup.
Syntactic JWS presence in this lifecycle reader is not admission evidence.
The existing modern schema1 contract is unchanged and is not accepted as TLS2.

TLS2 has one fixed certificate identity mode: the supplied server certificate
is the exact pinned leaf, not a general trust-store or a selectable insecure
option. The helper requires certificate-chain verification and compares the
connected peer's DER SHA256 before sending an HTTP request. Hostname matching
is deliberately replaced by this exact leaf pin, matching Incus's pinned-server
identity model. Redirects, environment proxies and Unix-socket fallback are
refused. The root handoff must still qualify the real private endpoint and
certificate/project restrictions.

Before create, the helper plans resources from the selected Incus project,
its default root device, owned instances and actual storage-pool usage. TLS
requires finite positive CPU, memory and disk quotas. The plan checks both
aggregate and any configured per-pool disk quota. A new VM needs its requested
root disk **plus** its state filesystem: the root device's explicit state size,
or 500 MiB by default on Incus 7.6. Containers do not have that VM state charge.
The create request applies CPU, RAM, root size and VM state size together with
the owner and network. This also works with a default profile that declares
only the root device and its pool.

An exact-owner rerun uses existing quota allocations for the same instance
type, and checks new disk bytes against current pool headroom. It never adds
configured disk sizes to physical free space or assumes another instance will
shrink. A VM root cannot shrink; growth requires a verified explicit state
size because Incus reapplies that state quota during root resizing. An unchanged
legacy VM can still rerun without changing its state volume.

Local and TLS create require actual free RAM for all requested guests before
mutation: the lifecycle stops and restarts existing guests. A configured limit
or future stop does not prove freed RAM. These observations are not reservations.
The upstream root allocator must reserve the whole cell, including the VM state
filesystem, and account for other leases and workloads. The default unlimited
project is refused for TLS.

Required API permissions are read-only server resources, the bound project and
its state, its default profile, and selected storage-pool resources. Any missing
permission or unsupported response blocks before creation and reports a fixed
failure category. Restricted TLS access to these endpoints must be tested on
the installed Incus version; a root Unix-socket observation does not prove it.

The remote VM branch does not inspect the controller's `/dev/kvm`; it checks
the authenticated server's declared VM driver and then still requires actual
`--vm` creation, start, agent execution and guest IPv4/route/DNS checks. A qemu
declaration alone is never VM evidence. The TLS branch performs no local
`systemctl`, sudo or host-firewall operation. Only an upstream-qualified
Incus-native firewall disposition is admitted. A recorded firewalld lifecycle
is retained for the accepted root collector rather than changed remotely.
Capture and destroy recheck the same TLS context and exact project. Expired or
unusable lease access fails closed; the accepted root recovery path must handle
cleanup that cannot complete through that lease. No result is promoted to PASS
because the ownership-filtered finalizer was unable to reach the server.

The pinned Incus 7.6 TLS contract uses a Root-precreated managed bridge in the
default project, inherited by the lease project with `features.networks=false`.
Before lifecycle access the consumer reads the lease project, default profile,
and deterministic bridge through its lease-scoped client. It requires
`restricted=true`, managed NICs and disks, `restricted.networks.access` equal to
the one native-cell-derived bridge, and `restricted.storage-pools.access` equal
to the default profile's one selected root pool. Empty or multiple access lists
are refused. The Root-prepared bridge must have this exact cell owner, IPv4
DHCP/NAT and Incus firewall enabled, and IPv6 disabled. Each allowed visible `used_by`
entry is exactly `/1.0/instances/<declared-name>?project=<lease-project>`;
unqualified, foreign-project, alternate-path and noncanonical URLs are refused.

Incus 7.6 returns an empty `config: {}` for an inherited default-project bridge
when the restricted certificate has view access without edit access. Missing,
null, or non-mapping config is refused. A nonempty config must satisfy all owner,
subnet, DHCP/NAT/firewall/IPv6 and DNS checks and match the Root-signed facts.
The lease client receives no default-project trust or edit permission.

### TLS2 runtime projection

The admitted TLS2 binding requires exactly these runtime fields:
`firewall_controller`, `bridge`, and `storage_pool`. `firewall_controller` is
`incus`; `bridge` contains exactly `name`, `project`, `owner`, `ipv4_address`,
`dns_domain`, `dhcp`, `nat`, `firewall`, and `ipv6_address`. Its project is
`default`, IPv6 is `none`, and DHCP/NAT/firewall are actual JSON `true` values.
The network name derives from the exact owner and the selected pool must match
the lease restriction and default root-disk profile. Minimal runtime bindings
and extra approval flags are refused by this consumer.

Root derives these nonsecret facts from the sealed cell, checks the actual full
bridge ownership/config before materialization and publication, and signs them
with the binding, context-file digests and current lease. The Root host must
verify that admission before engine entry. Parsing this projection in the
consumer creates no signature or authorization. When the API config is exactly
empty, the consumer uses the Root-bound subnet for the existing deterministic
static fallback and bridge DNS. Guest DHCP, IPv4, route and `getent` checks all
remain required; no guest-derived gateway or caller flag replaces Root facts.

Consumer evidence distinguishes redacted config, Root-signed configuration
facts, and lease-visible resource users. It records no direct owner-label match
for hidden config and does not attest hidden current configuration or global
absence of foreign users. Root issuer and finalizer must retain their full
ownership/config and unfiltered usage checks. The pinned implementation is in
[networkGet](https://github.com/lxc/incus/blob/8f5e6c2235f6424ec59d3dc06f12e344a4a416e2/cmd/incusd/networks.go#L1109)
and the [TLS authorizer](https://github.com/lxc/incus/blob/8f5e6c2235f6424ec59d3dc06f12e344a4a416e2/internal/server/auth/driver_tls.go#L90).

TLS create only reads and attaches to that existing bridge; it never creates,
sets or deletes networks and never mutates host firewall state. Missing or
incorrect Root preparation fails closed. Local mode keeps its existing bridge
create/reconcile/delete behavior. TLS instance and VM initialization, start,
agent readiness, guest address/DNS checks, capture and exact-owner destruction
remain required. TLS destroy reports `network_cleanup_deferred=true`,
`network_cleanup_authority="root"`, and no network deletion attempt. It permits
only the deterministic bridge to remain after all exact-owned instances are
gone. Root must independently recheck ownership and the complete unfiltered
network users, then remove the bridge after owned instance/VM teardown; this
consumer result does not claim that Root cleanup occurred.

Root publisher/template wiring and actual Incus 7.6 restricted-certificate read,
attach and denial behavior remain native qualification gates. The deterministic
name, context parsing and fixture results add no unsigned admission authority.

Deterministic transport tests are `test_incus_tls_transport.py` and
`test_incus_lifecycle.py` under `tests/unit/`. They include real loopback mutual
TLS/pin/redirect behavior, resource and owner/type boundary fixtures, and the
installed connection plugin's option/command entry. They are component tests,
not a live Incus, VM, Heavy or Application Acceptance result. Run them in the
repository's pinned Devtools EE; ordinary local PR preflight remains
`pre-commit run --all-files` through that EE.

## Execution

```bash
incus version
incus info
python3 scripts/validate-role-coverage.py matrix --profile heavy
# First export the ephemeral identity and secrets from docs/testing/keycloak.md.
run_keycloak_profile keycloak-heavy
```

RHEL image variables must reference approved, entitlement-compliant images.
Missing images fail as `infrastructure-error`; an Ubuntu substitute must never
make a RHEL cell pass.

Expensive environments use concurrency controls. Evidence is captured before
cleanup, including failure paths. Network ready, attachment, pre-destroy, and
post-destroy records are stored below
`$MOLECULE_TEST_ARTIFACTS/incus-lifecycle/<scenario>/<target>/`. Destroy enumerates
labels, removes only exact-owner matches, retains foreign resources, and fails if
any exact-owned instance remains. Local cleanup also requires all exact-owned
bridges to be absent; TLS cleanup defers the one declared bridge to Root as
described above.

For a concurrent local run, set a unique instance name while keeping one owner
value for create, cleanup, and destroy:

```bash
MOLECULE_TEST_OWNER="local/${USER}/$(date -u +%Y%m%dT%H%M%S)-rsyslog"
export MOLECULE_TEST_OWNER
export MOLECULE_TEST_INSTANCE="rsyslog-${USER}-$$"
export MOLECULE_TEST_TARGET=ubuntu-24.04
molecule test -s rsyslog-lifecycle-incus_heavy
```

If a run is interrupted, rerun `molecule destroy -s <scenario>` with the same
instance-name environment. The persisted local identity selects only that run's
resources. If you supplied an explicit owner, export the same value again. Do
not delete a name based on convention alone; verify the exact label.
