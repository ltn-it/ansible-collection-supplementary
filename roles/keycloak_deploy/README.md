# keycloak_deploy

Deploy Keycloak as a dedicated Podman pod and (optionally) deploy PostgreSQL via
`postgres_deploy`.

## Requirements

`postgres_deploy` when `keycloak_deploy_manage_postgres` is enabled. Podman and
the operating-system preparation declared by the caller are required.

## Variables

See `roles/keycloak_deploy/defaults/main.yml`.

Key variables:
- `keycloak_deploy_image`
- `keycloak_deploy_pod_manifest_path`
- `keycloak_deploy_host_data_dir`
- `keycloak_deploy_port`
- `keycloak_deploy_host_ip`
- `keycloak_deploy_manage_postgres`
- `keycloak_deploy_postgres_image`
- `keycloak_deploy_postgres_pod_name`
- `keycloak_deploy_postgres_pod_manifest_path`
- `keycloak_deploy_db_host`
- `keycloak_deploy_db_port`
- `keycloak_deploy_db_name`
- `keycloak_deploy_db_user`
- `keycloak_deploy_db_password`
- `keycloak_deploy_admin_user`
- `keycloak_deploy_admin_password`
- `keycloak_deploy_generate_secrets`
- `keycloak_deploy_manage_systemd`
Proxy headers require valid `keycloak_deploy_proxy_trusted_addresses`, rendered
as `KC_PROXY_TRUSTED_ADDRESSES`. Edge TLS keeps Keycloak on host loopback,
attaches NGINX and Keycloak to a pinned private Quadlet network, and trusts only
the NGINX pod address.

Managed bridge PostgreSQL requires a private `keycloak_deploy_db_host` matching
its pinned network IP or the exact managed PostgreSQL pod/container DNS name; readiness
uses the published host endpoint. Arbitrary external DNS names and Keycloak
loopback are rejected. DNS mode requires network-local Podman name resolution,
an explicit resolver firewall allowance, and positive/negative DNS evidence;
it does not replace static firewall addresses or trusted proxy CIDRs.

`keycloak_deploy_native_network_migration` is a default-off, coupled transition
for two already active, root-owned native Quadlets without drop-ins. Set
`keycloak_deploy_native_previous_networks` to the exact prior `keycloak` and
`postgres` Network lists, including explicit empty lists for default-network
units. The database endpoint must be its declared IPv4 or exact managed pod/container
DNS name; Keycloak must have its own address on the same database network.
Bind `keycloak_deploy_native_network_runtime_names` explicitly from each Network
entry basename (including a `.network` suffix where used) to its actual Podman
network name. Runtime verification compares names and addresses, not addresses
alone. Before stopping either service, actual images, data mounts and database
endpoint must match the proven original configuration. Rollback verifies the
original network names and database endpoint; explicit prior addresses remain
pinned, while addresses on implicit default networks may legitimately change.
An empty prior Network list is supported only when runtime inspection proves
exactly `podman-default-kube-network`, the Podman non-host kube default. Arbitrary
single attachments or additional manually attached networks fail before either
service stops: an empty restored Quadlet cannot reconstruct them. This implicit
contract is verified against Podman 4.9.3, not a claim of live migration acceptance.

Podman 4.9.3 kube play registers the YAML container name as a network alias.
Thus a managed `postgres` container can retain a different pod/unit identity.
This does not authorize arbitrary aliases or shared database credentials.
Because Podman 4.9 does not reliably publish that identity between separate
Kube pods, the Keycloak Pod uses the supported `spec.hostAliases` field to bind
the exact managed name to PostgreSQL's already validated private static address.
The role then verifies from the running Keycloak container that the name resolves
exclusively to that address before accepting application readiness.
During native cutover, `getent ahostsv4` inside the actual Keycloak container
must return only the uniquely bound private PostgreSQL address. Missing tooling,
failed resolution or a different/additional address causes transaction recovery.
Network DNS enablement, resolver isolation and its firewall allowances remain
caller-owned prerequisites; the role does not enable external DNS forwarding.

The transition runs before either ordinary deploy role. It snapshots both
manifests and Quadlets in memory under `no_log`, preserves images and data paths,
stops Keycloak before PostgreSQL, and writes only bound configuration through
descriptor-relative `atomic_path`. PostgreSQL readiness precedes Keycloak health
acceptance. A failed cutover restores both original configurations; external
content or parent-identity drift fails closed rather than being overwritten.
Captured Pod bytes are checked for duplicate mapping keys before YAML conversion.
Rollback accepts computed target bytes only for files the cutover can write;
the untouched PostgreSQL manifest must retain its original checksum. Both the
batch preflight and final per-file check enforce this ownership boundary.
The transition does not support inactive, legacy, rootless, administrator-edited
or mixed prior/desired controllers. Controller termination is not a durable
automatic rollback guarantee; recovery requires retained authoritative source
configuration. Do not claim live migration acceptance from preparation tests.

Subsequent native reconciliation compares the complete current manifest with
the normally rendered role template, including scalar types and sequence order.
Formatting-only differences preserve the existing bytes and reconcile private
file permissions without restarting. Real configuration changes retain the
ordinary transactional render/restart/rollback path. Invalid or ambiguous YAML
fails comparison rather than being treated as equal.

`tests/unit/test_native_network_transaction.py` executes the production Ansible
cutover/rescue/always control flow with isolated, fault-injected I/O. It verifies
the exact failure boundary, paired recovery after stop/write/readiness failures,
external-drift refusal, and snapshot disposal. Its unchanged-plan case proves
the cutover is skipped, not whole-role idempotence. These deterministic tests do
not prove live Podman readiness, DNS resolution or atomic filesystem semantics;
the actual component profiles and live acceptance remain required.

Exactly one lifecycle controller owns the pod: native `.kube` Quadlet through
`lit.foundational.podman_systemd`, or explicit fail-closed direct kubeplay.
Both verify the active database endpoint before health acceptance. Quadlet
takeover disables only the exact legacy unit; its `<pod-name>-pod.service` name
avoids `keycloak.service` collisions. Missing systemd fails prechecks.

### Rootless user scope (experimental)

Set `keycloak_deploy_systemd_scope: user` explicitly to use native User Quadlets.
All three runtimes are rendered as Kubernetes YAML and owned exclusively by
`lit.foundational.podman_systemd` through `.kube` units. The caller supplies
Podman, a genuinely non-root account and home, automatic user-systemd startup,
writable persistent directories, TLS material and privileged-port permission.
This path does not prepare the operating system. On SELinux-enforcing hosts,
prepared bind paths must have `container_file_t` labels: existing bind mounts
are not relabeled by [Podman kube play](https://docs.podman.io/en/stable/markdown/podman-kube-play.1.html).

Credentials come from encrypted caller inputs and appear only in owner-readable
runtime manifests rendered with `no_log` and disabled diffs. PostgreSQL credentials
must continue to match an existing database. No database migration or downgrade
is implied. Old experimental `.container` units are rejected rather than silently
creating a second lifecycle owner.

The private network name and addresses are configurable. PostgreSQL and the
Keycloak application endpoint have no host publication; optional management uses
the configured host port on loopback, with container port 9000. Keycloak maps the
host account to its configured image UID through Podman's keep-id annotation.
Only xforwarded proxy headers are currently supported.

Nginx candidates are validated on the actual private network before installation.
The last successfully applied configuration, manifest and TLS checksums decide
whether the shared lifecycle must recreate the runtime. Failed validation retains
the prior installed configuration; failed reconciliation retains pending state.
Same-path TLS renewal is detected by content and recreates the bind mounts.
`nginx_deploy_rootless_after` defines user-unit boot ordering for the edge.
Check mode predicts manifests/configuration but does not reconcile services.

Existing system-scope platform/profile claims do not establish rootless production
support. Rootless remains experimental; the caller owns PKI, trust and backup/
restore planning. Container names follow Podman's kube pod/container naming.

## Dependencies

Runtime composition uses `lit.supplementary.postgres_deploy` when PostgreSQL is
managed by this role and `lit.foundational` Podman lifecycle roles declared by
the collection.

## Example Playbook

```yaml
- name: Deploy Keycloak
  hosts: wunderboxes
  become: true
  roles:
    - role: lit.supplementary.keycloak_deploy
      vars:
        keycloak_deploy_manage_postgres: true
        keycloak_deploy_manage_systemd: true
        keycloak_deploy_networks:
          - keycloak-access.network:ip=10.89.40.2
        keycloak_deploy_postgres_networks:
          - keycloak-access.network:ip=10.89.40.3
        # Requires verified network-local DNS without external forwarding.
        keycloak_deploy_db_host: postgres
        keycloak_deploy_admin_user: admin
        keycloak_deploy_generate_secrets: false
        keycloak_deploy_admin_password: "{{ vault_keycloak_admin_password }}"
        keycloak_deploy_db_password: "{{ vault_keycloak_db_password }}"
```

## License

MIT

## Author

Lightning IT

## Enterprise test disposition

- Classification: web application deployment.
- Maturity: production-supported through the registry-required Keycloak
  component profiles.
- Supported platform: Ubuntu 24.04. RHEL 9 and RHEL 10 remain candidates until
  their exact-commit matrices pass on approved images.
- Tiny: real deployment, PostgreSQL, readiness, OIDC, version, permissions, and
  idempotency.
- Heavy: PostgreSQL, LDAP integration, persistence, restart, an isolated
  destructive table restore drill, authentication, and authorization. An
  independent LDAP client verifies the ephemeral CA and service hostname.
- Application Acceptance: browser/OIDC login, protected endpoints, positive and
  negative authorization, invalid credentials, logout, and session invalidation.
- Evidence: meaningful JUnit/Allure, redacted logs, environment metadata, and
  the collection evidence manifest.
- Limitations: the restore drill is intentionally scoped to an isolated probe
  table and is not a whole-database disaster-recovery claim. No supported
  upgrade path or separate Keycloak JVM truststore-enforcement claim is made.

Run the three scenarios documented in
[`docs/testing/keycloak.md`](../../docs/testing/keycloak.md). No external service
credential is required; use ephemeral test credentials only.

Existing rootless networks must match the declared subnet exactly. The role
inspects that network before writing managed files and rejects a live subnet
change. A coordinated network migration is outside this experimental path.

The experimental user-scope path requires a canonical IPv4 network with distinct usable static member addresses and rejects nonempty `keycloak_deploy_env_extra`; additional environment settings are not silently ignored.

User scope supports the standard `start` command, no extra startup arguments and the root context path. Non-default startup, database vendor/port, container mount paths, host networking or native migration settings are rejected before managed writes. Its derived API URL uses the configured HTTPS hostname; an explicit API URL still takes precedence. System-scope URL derivation is unchanged.

User scope requires the PostgreSQL service name derived from its pod (`<postgres-pod>-pod`). Unsupported `keycloak_deploy_postgres_systemd_unit_name` overrides are rejected before managed writes, preserving the shared lifecycle owner and Keycloak dependencies. Renaming an existing stateful service requires a separate planned transition.
