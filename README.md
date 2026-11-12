# lit.supplementary

<!-- BEGIN LIT_SHARED_RELEASE_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.

See [RELEASE.md](./RELEASE.md) for:

- branch and release flow
- required quality checks
- test matrix
- release evidence
- artifact publishing
- supported repository-specific release behavior

Repository classification: **Ansible Collection**.
Required test profiles: `pre-commit, lint, light, molecule-light, molecule-heavy-incus, release-validation`.
Publishing targets: `github-release, ansible-galaxy`.

## Supported and tested platforms

Support is role- and profile-specific; there is no collection-wide platform
claim. [`meta/role-coverage.yml`](meta/role-coverage.yml) is authoritative, and
the generated [role coverage table](docs/testing/role-coverage.md) separates
proven targets from candidate platforms and external blockers. A platform is
supported only when every mandatory registry cell passes for the exact commit.

<!-- END LIT_SHARED_RELEASE_MODEL -->

<!-- BEGIN LIT_QUALITY_BADGES -->

[![CI](https://github.com/lightning-it/ansible-collection-supplementary/actions/workflows/collection-ci.yml/badge.svg?branch=develop)](https://github.com/lightning-it/ansible-collection-supplementary/actions/workflows/collection-ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/lightning-it/ansible-collection-supplementary?sort=semver)](https://github.com/lightning-it/ansible-collection-supplementary/releases/latest)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lightning-it/ansible-collection-supplementary/badge)](https://scorecard.dev/viewer/?uri=github.com/lightning-it/ansible-collection-supplementary)
[![Ansible Galaxy](https://img.shields.io/ansible/collection/v/lit/supplementary?label=Ansible%20Galaxy)](https://galaxy.ansible.com/ui/repo/published/lit/supplementary/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

<!-- END LIT_QUALITY_BADGES -->

## Wunderbox Identity Stack PoC

This repository now includes production-like PoC artifacts for a single-node
identity stack on a Wunderbox host:

- 389 Directory Server in a container
- Keycloak in a container with PostgreSQL backend
- LDAP federation from Keycloak to 389ds
- Nested group resolution via 389ds MemberOf plugin fixup
- OIDC `groups` claim emitted from Keycloak tokens

### Requirements

- Podman with `podman kube play`
- `envsubst` (from `gettext`) for rendering manifest variables
- local access to image artifacts (runtime is offline-capable)

Pinned images:

- `docker.io/389ds/dirsrv:3.1@sha256:af99ccf42c1cd02799d674ffdee3612a1bbd426c1a8a636da67ea349659ee5e0`
  (via the local wrapper image build)
- `quay.io/keycloak/keycloak:26.5.4@sha256:ae8efb0d218d8921334b03a2dbee7069a0b868240691c50a3ffc9f42fabba8b4`
- `docker.io/library/postgres:16@sha256:eb4759788a2182f08257135e61a34f2cfc3c2914079f3465d64ee62350f4d081`

### Files

- Manifest: `manifests/identity-stack.pod.yaml`
- LDAP image: `containerfiles/ldap/Containerfile`
- LDAP bootstrap entrypoint: `containerfiles/ldap/entrypoint-wrapper.sh`
- LDAP seed: `bootstrap/seed.ldif`
- Keycloak bootstrap: `bootstrap/keycloak-bootstrap.sh`

### Quickstart

1. Create host directories and secrets.

```bash
export IDENTITY_ROOT=/srv/wunderbox/identity

sudo mkdir -p \
  "$IDENTITY_ROOT"/{ldap,ldap-tls,pg,keycloak,bootstrap,secrets}

sudo cp -f bootstrap/seed.ldif "$IDENTITY_ROOT/bootstrap/seed.ldif"
sudo cp -f bootstrap/keycloak-bootstrap.sh "$IDENTITY_ROOT/bootstrap/keycloak-bootstrap.sh"
sudo chmod 0755 "$IDENTITY_ROOT/bootstrap/keycloak-bootstrap.sh"

printf '%s\n' '<set-a-local-directory-manager-password>' \
  | sudo install -m 0600 /dev/stdin "$IDENTITY_ROOT/secrets/ds_dm_password"
printf '%s\n' '<set-a-local-postgres-password>' \
  | sudo install -m 0600 /dev/stdin "$IDENTITY_ROOT/secrets/postgres_password"
printf '%s\n' '<set-a-local-keycloak-admin-password>' \
  | sudo install -m 0600 /dev/stdin "$IDENTITY_ROOT/secrets/keycloak_admin_password"

sudo chmod 0600 "$IDENTITY_ROOT/secrets/"*
```

2. Build the local LDAP wrapper image.

```bash
podman build \
  -t localhost/wunderbox-ldap:3.1-bootstrap \
  -f containerfiles/ldap/Containerfile \
  .
```

3. Render and start the pod.

```bash
: "${IDENTITY_ROOT:=/srv/wunderbox/identity}"
: "${BASE_DN:=dc=wunderbox,dc=local}"
: "${LDAP_HOSTNAME:=ldap.wunderbox.local}"
: "${LDAP_HOST_PORT:=3389}"
: "${LDAPS_HOST_PORT:=3636}"
: "${KEYCLOAK_HOSTNAME:=keycloak.wunderbox.local}"
: "${KEYCLOAK_HOST_PORT:=8080}"
: "${KEYCLOAK_HTTP_PORT:=8080}"
: "${KEYCLOAK_DB_NAME:=keycloak}"
: "${KEYCLOAK_DB_USER:=keycloak}"
: "${KEYCLOAK_ADMIN:=admin}"

envsubst < manifests/identity-stack.pod.yaml > /tmp/identity-stack.rendered.yaml
podman kube play /tmp/identity-stack.rendered.yaml
```

4. Verify LDAP nested `memberOf` transitivity (acceptance test #1).

```bash
LDAP_DM_PASSWORD="$(sudo cat "$IDENTITY_ROOT/secrets/ds_dm_password")"

podman exec -i identity-stack-ldap ldapsearch -LLL -x \
  -H ldap://127.0.0.1:3389 \
  -D "cn=Directory Manager" \
  -w "$LDAP_DM_PASSWORD" \
  -b "uid=alice,ou=people,dc=wunderbox,dc=local" \
  memberOf
```

Expected: `memberOf` contains both:

- `cn=aio-wbx-ops,ou=groups,dc=wunderbox,dc=local`
- `cn=aio-wbx-admins,ou=groups,dc=wunderbox,dc=local`

5. Bootstrap Keycloak federation and OIDC mappers.

```bash
./bootstrap/keycloak-bootstrap.sh
```

6. Verify login + token groups claim (acceptance tests #2 and #3).

```bash
TOKEN="$(
  curl -fsS \
    -d grant_type=password \
    -d client_id=demo \
    -d username=alice \
    -d password='<alice-demo-password>' \
    "http://127.0.0.1:8080/realms/wunderbox/protocol/openid-connect/token" \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
)"

python3 - "$TOKEN" <<'PY'
import base64
import json
import sys

tok = sys.argv[1]
payload = tok.split(".")[1]
payload += "=" * (-len(payload) % 4)
data = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
print("groups =", data.get("groups"))
PY
```

Expected groups include `aio-wbx-ops` and `aio-wbx-admins` (path or plain group names depending on mapper behavior).

7. Rerun bootstrap for idempotency check (acceptance test #4).

```bash
./bootstrap/keycloak-bootstrap.sh
```

### Troubleshooting

- 389ds plugin and status checks:

```bash
podman exec -it identity-stack-ldap dsconf localhost plugin memberof show
podman exec -it identity-stack-ldap dsconf localhost plugin memberof fixup dc=wunderbox,dc=local
podman exec -it identity-stack-ldap dsctl localhost status
```

- Keycloak logs and bootstrap rerun:

```bash
podman logs -f identity-stack-keycloak
./bootstrap/keycloak-bootstrap.sh
```

- Full reset:

```bash
podman kube down /tmp/identity-stack.rendered.yaml || true
sudo rm -rf /srv/wunderbox/identity/*
```

Supplementary Ansible collection for ModuLix / Lightning IT.
It includes service deployment and Configuration-as-Code roles such as
`keycloak_deploy`, `keycloak_cac`, `forgejo_deploy`, `forgejo_cac`,
`semaphore_deploy`, `semaphore_cac`, `nessus_deploy`, `nessus_cac`,
`postgres_deploy`, `checkmk_deploy`, `loki_deploy`,
`alloy_deploy`, `grafana_deploy`, `cloudflared`, and
`cloudflare_warp`.

## Wunderbox Monitoring and Logging PoC

The Wunderbox PoC monitoring/logging stack is intentionally small and
single-host:

- Checkmk is the primary monitoring system.
- Loki, Alloy, and Grafana provide the technical logging stack.
- Loki is internal by default on `127.0.0.1:3100`.
- Grafana and Checkmk are the only public reverse-proxy vhosts added by
  `playbooks/wunderbox_monitoring_logging.yml`.
- Prometheus and Alertmanager are intentionally not included in this PoC scope.
- Forgejo Runner is intentionally excluded from the Wunderbox playbook and may be
  deployed later on a separate VM if customer CI/CD is required.

Example invocation:

```bash
ansible-playbook -i inventory.yml \
  playbooks/wunderbox_monitoring_logging.yml
```

Example inventory snippet:

```yaml
all:
  hosts:
    wunderbox02.prd.dmz.corp.l-it.io:
      grafana_deploy_public_fqdn: grafana.wunderbox02.prd.dmz.corp.l-it.io
      checkmk_deploy_public_fqdn: checkmk.wunderbox02.prd.dmz.corp.l-it.io
      grafana_deploy_admin_password: "{{ vault_wunderbox02_grafana_admin_password }}"
      checkmk_deploy_admin_password: "{{ vault_wunderbox02_checkmk_admin_password }}"
```

Service catalog:

| Service | Exposure | Login |
|---|---|---|
| Checkmk | `https://checkmk.<wunderbox-domain>` | `cmkadmin`, password from HC Vault or Ansible Vault |
| Grafana | `https://grafana.<wunderbox-domain>` | `admin`, password from HC Vault or Ansible Vault |
| Loki | Internal only, `http://127.0.0.1:3100` | No public login |
| Alloy | Agent only | No user login |

Persistent data defaults:

| Role | Data path |
|---|---|
| `checkmk_deploy` | `/srv/checkmk/data` |
| `loki_deploy` | `/srv/loki/data` |
| `alloy_deploy` | `/srv/alloy/data` |
| `grafana_deploy` | `/srv/grafana/data` |

Secrets:

- Grafana admin: HC Vault path `{{ inventory_hostname }}/grafana/admin`, or
  `grafana_deploy_admin_password` from Ansible Vault.
- Checkmk admin: HC Vault path `{{ inventory_hostname }}/checkmk/admin`, or
  `checkmk_deploy_admin_password` from Ansible Vault.
- No plaintext generated secret files are written unless the explicit
  `*_allow_local_secret_files=true` break-glass variable is set.

Alloy default log collection:

- journald/systemd
- Podman container log files when present
- NGINX, Vault operational, Keycloak, Nexus, and Forgejo log paths under `/srv`
- Vault audit logs are disabled by default with
  `alloy_deploy_collect_vault_audit_logs: false`

Checkmk object registration is represented by
`checkmk_deploy_monitoring_targets` and rendered as hook data for a future
Checkmk CaC role. The first implementation deploys Checkmk but does not yet
create Checkmk hosts/services through its API.

## Usage

Install directly from the repo/branch:

```bash
ansible-galaxy collection install \
  git+https://github.com/lightning-it/ansible-collection-supplementary.git,develop
```

Example playbook:

```yaml
- hosts: keycloak
  gather_facts: false
  connection: local

  roles:
    - role: lit.supplementary.keycloak_cac
```

## Development

- `galaxy.yml` defines the collection metadata (namespace `lit`, name
  `supplementary`, license `MIT`).
- Core collection dependencies are declared in `galaxy.yml`.
- Red Hat/AAP extension collections are intentionally excluded from the core
  `galaxy.yml` dependency graph. The authoritative, exactly pinned AAP overlay
  is [`collections/requirements-rh.yml`](collections/requirements-rh.yml):
  `ansible.controller`, `infra.aap_configuration`,
  `infra.aap_utilities`, `infra.controller_configuration`, and
  `infra.ee_utilities`. Install that complete overlay from configured Galaxy
  and Automation Hub sources in the protected AAP execution environment.
- Shipped role image defaults are tag-and-digest pinned and inventoried in
  [`meta/source-dependencies.yml`](meta/source-dependencies.yml); validation and
  SBOM behavior are documented under
  [shipped source dependencies](docs/testing/source-dependencies.md).
- AAP development and testing uses Ansible-managed Incus VMs. Incus instance
  lifecycle is owned by `lit.ubuntu.incus_instance`; this collection only owns
  AAP role behavior:
  - [docs/testing/README.md](docs/testing/README.md)
  - [docs/testing/aap.md](docs/testing/aap.md)
- Canonical role sources live in `roles/`; build with `ansible-galaxy
  collection build`.
- Molecule scenario `keycloak-tiny` performs fast, real deployment and
  technical verification on isolated self-hosted runtime jobs. Exact
  same-repository pull-request heads require release-team environment approval;
  fork heads fail closed, and every protected SHA is tested again after merge.
- Molecule scenario `keycloak-heavy` validates PostgreSQL, LDAP integration,
  persistence, restart, backup creation, and authorization behavior. Restore,
  upgrade, and trusted TLS remain explicit limitations until proved.
- Molecule scenario `keycloak-application-acceptance` validates browser login,
  sessions, OIDC claims, and positive and negative authorization. See
  [Keycloak testing](docs/testing/keycloak.md) for commands and evidence.
- All other Basic and legacy Heavy scenarios have an explicit registry
  disposition. Stub/Skip-mode, fake-runtime, and partial scenarios remain useful
  development checks but are not production Tiny, Heavy, or Application
  Acceptance passes.
- AAP, Nessus, Cloudflare, and ESXi profiles retain explicit licence, service,
  or infrastructure blockers rather than reporting an unavailable integration
  as success.
- `gitlab_runner` is deprecated while it remains an acknowledged stub. Nexus
  and the remaining incomplete implementations are experimental until their
  mandatory profiles are real and green.

## G06 operating continuation

The three G06 operating cases remain separate from business quality results.
Their caller permits the original Main transition from `90e7216b5d08` and one
functional follow-up from `14e3abd5d1fa`, on attempt one with the existing eligible
user and matching triggering actor. The failed original run remains failed.
The Root service must independently bind the exact follow-up Main commit and
native run to the original failure and verified absence of consumed intake.
This caller condition grants no lease or retry authority. Both ordinary profiles
must pass before the serial failure, broker cancellation and expiry cases run.
Actual four-hour retention, cleanup and local root-mail delivery remain required;
a skipped case or successful local test does not satisfy operating acceptance.

## Local checks

This repository uses **pre-commit** and a shared devtools container
(`ee-wunder-devtools-ubi9`) to keep linting and runtime tests consistent between
local development and CI.

### 1. Install pre-commit

If you haven't already:

```bash
pip install pre-commit
pre-commit install
```

This installs the standard `pre-commit` hook for this repo (YAML, Ansible,
Molecule, etc.).

### 2. Run all linters locally

Run every configured repository hook, including policy generation, Python,
YAML, Ansible, Markdown, shell, workflow, collection-smoke, and discoverable
root-level Molecule checks:

```bash
pre-commit run --all-files
```

Container-based execution (recommended):

```bash
H="$HOME/.cache/wunder-home"
mkdir -p "$H/.docker"

podman run --rm -it \
  --userns keep-id --user "$(id -u):$(id -g)" \
  --security-opt label=disable \
  -v "$PWD":"$PWD":z \
  -v "$HOME/.cache":"$HOME/.cache":z \
  -v "/run/user/$(id -u)/podman/podman.sock":"/run/user/$(id -u)/podman/podman.sock" \
  -w "$PWD" \
  -e HOME="$H" \
  -e DOCKER_CONFIG="$H/.docker" \
  -e XDG_CACHE_HOME="$HOME/.cache" \
  -e PRE_COMMIT_HOME="$HOME/.cache/pre-commit" \
  -e DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock" \
  -e GIT_CONFIG_COUNT=1 \
  -e GIT_CONFIG_KEY_0=safe.directory \
  -e GIT_CONFIG_VALUE_0="$PWD" \
  quay.io/l-it/ee-wunder-devtools-ubi9:v1.9.2 \
  pre-commit run --all-files
```

The Molecule hook discovers scenarios under `molecule/`. Registry disposition,
not successful execution of an experimental Basic scenario, determines whether
a result is a production support claim. Protected Incus scenarios require an
explicit opt-in and the resources documented in
[Keycloak testing](docs/testing/keycloak.md).

### 3. Run the collection smoke test

For a full **collection smoke test** (build + install + example playbook via FQCN):

```bash
pre-commit run collection-smoke --all-files --hook-stage manual
```

This will:

1. build the `lit.supplementary` collection inside the devtools container,
2. install the built tarball into `/tmp/wunder/collections`,
3. run the example playbook:

   ```bash
   ansible-playbook -i localhost, playbooks/example.yml
   ```

   using the installed collection via `ANSIBLE_COLLECTIONS_PATH=/tmp/wunder/collections`.

Use this smoke test whenever you want to verify that the collection is:

- buildable,
- installable,
- and usable via FQCN (`lit.supplementary.keycloak_cac`) before pushing or tagging a release.

## Security

See [SECURITY.md](./SECURITY.md) for supported versions and vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution and review expectations.

## License

See [LICENSE](./LICENSE).

<!-- BEGIN LIT_RELEASE_QUALITY_MODEL -->

## Managed release metadata

This repository follows the Lightning IT shared release and quality model.
The generated role coverage report shows the current supported and candidate
matrix. Releases produced under the enterprise role-quality architecture store
exact per-version proof as `release-evidence.md` and `release-evidence.json`.
Releases are created from the protected `main` branch after a reviewed `develop -> main` release promotion.
Collection releases validate collection sanity, Molecule scenarios, build integrity, and Ansible Galaxy publishing where enabled.

See:

- [RELEASE.md](./RELEASE.md)
- [TESTING.md](./TESTING.md)
- [GitHub Releases](https://github.com/lightning-it/ansible-collection-supplementary/releases)

Repository classification: **Ansible Collection**.
Required test profiles: `pre-commit, lint, light, molecule-light, molecule-heavy-incus, release-validation`.
Publishing targets: `github-release, ansible-galaxy`.

<!-- END LIT_RELEASE_QUALITY_MODEL -->

<!-- BEGIN LIT_COMPATIBILITY_MATRIX -->

## Supported and Tested Platforms

The generated [role coverage report](docs/testing/role-coverage.md) is the
current matrix. Release attachments contain the executed role/profile/target
matrix for that exact version; configured or candidate cells are never
synthesized as passes.

<!-- role-coverage-table:start -->

| Role | Maturity | Supported targets | Tiny | Heavy | Application Acceptance |
|---|---|---|---|---|---|
| aap | experimental | — | experimental | blocked-external-license | blocked-external-license |
| aap_baseline | experimental | — | experimental | blocked-external-license | not-applicable |
| aap_bootstrap | experimental | — | experimental | blocked-external-license | not-applicable |
| aap_cac | experimental | — | experimental | blocked-external-license | blocked-external-license |
| aap_deploy | experimental | — | experimental | blocked-external-license | blocked-external-license |
| aap_destroy | experimental | — | experimental | blocked-external-license | blocked-external-license |
| aap_host_prepare | experimental | — | experimental | blocked-external-license | not-applicable |
| aap_local_execution | experimental | — | experimental | blocked-external-license | blocked-external-license |
| aap_ops | experimental | — | experimental | blocked-external-license | blocked-external-license |
| aap_preflight | experimental | — | experimental | blocked-external-license | not-applicable |
| aap_prepare | experimental | — | experimental | blocked-external-license | not-applicable |
| aap_secrets | experimental | — | experimental | blocked-external-license | not-applicable |
| aap_tls | experimental | — | experimental | blocked-external-license | not-applicable |
| alertmanager_deploy | experimental | — | experimental | experimental | experimental |
| alloy_deploy | experimental | — | experimental | experimental | experimental |
| artifacts | experimental | — | experimental | experimental | experimental |
| checkmk_deploy | experimental | — | experimental | experimental | experimental |
| cloudflare_warp | experimental | — | experimental | blocked-external-service | blocked-external-service |
| cloudflared | experimental | — | experimental | blocked-external-service | blocked-external-service |
| coredns_config | experimental | — | experimental | experimental | experimental |
| coredns_deploy | experimental | — | experimental | experimental | experimental |
| coredns_ops | experimental | — | experimental | experimental | experimental |
| coredns_validate | experimental | — | experimental | experimental | not-applicable |
| dhcp_deploy | experimental | — | experimental | experimental | experimental |
| forgejo_cac | experimental | — | experimental | experimental | experimental |
| forgejo_deploy | experimental | — | experimental | experimental | experimental |
| forward_proxy | experimental | — | experimental | blocked-external-infrastructure | blocked-external-infrastructure |
| gitlab_runner | deprecated | — | deprecated | deprecated | deprecated |
| grafana_deploy | experimental | — | experimental | experimental | experimental |
| guacamole_deploy | experimental | — | experimental | experimental | experimental |
| hetzner_object_storage_cac | experimental | — | experimental | blocked-external-service | blocked-external-service |
| incus_esxi_image | experimental | — | experimental | blocked-external-license | blocked-external-license |
| incus_nested_esxi | experimental | — | experimental | blocked-external-infrastructure | blocked-external-infrastructure |
| keycloak | experimental | — | experimental | experimental | experimental |
| keycloak_backup_restore | experimental | — | experimental | experimental | experimental |
| keycloak_cac | production | ubuntu-24.04 | supported | supported | supported |
| keycloak_config | experimental | — | experimental | experimental | experimental |
| keycloak_deploy | production | ubuntu-24.04 | supported | supported | supported |
| keycloak_destroy | experimental | — | experimental | experimental | experimental |
| keycloak_ops | experimental | — | experimental | experimental | experimental |
| keycloak_preflight | experimental | — | experimental | experimental | not-applicable |
| keycloak_upgrade | experimental | — | experimental | experimental | experimental |
| keycloak_validate | experimental | — | experimental | experimental | not-applicable |
| loki_deploy | experimental | — | experimental | experimental | experimental |
| manage_esxi | experimental | — | experimental | blocked-external-infrastructure | blocked-external-infrastructure |
| minio_backup_restore | experimental | — | experimental | experimental | experimental |
| minio_bootstrap | experimental | — | experimental | experimental | experimental |
| minio_config | experimental | — | experimental | experimental | experimental |
| minio_deploy | experimental | — | experimental | experimental | experimental |
| minio_foundational | experimental | — | experimental | experimental | not-applicable |
| minio_ops | experimental | — | experimental | experimental | experimental |
| minio_validate | experimental | — | experimental | experimental | not-applicable |
| nessus_cac | experimental | — | experimental | blocked-external-license | blocked-external-license |
| nessus_deploy | experimental | — | experimental | blocked-external-license | blocked-external-license |
| netbox_deploy | experimental | — | experimental | experimental | experimental |
| nexus | experimental | — | experimental | experimental | experimental |
| nginx_config | experimental | — | experimental | experimental | experimental |
| nginx_deploy | experimental | — | experimental | experimental | experimental |
| nginx_ops | experimental | — | experimental | experimental | experimental |
| nginx_validate | experimental | — | experimental | experimental | not-applicable |
| openvpn | experimental | — | experimental | experimental | experimental |
| postgres | experimental | — | experimental | experimental | experimental |
| postgres_backup_restore | experimental | — | experimental | experimental | experimental |
| postgres_config | experimental | — | experimental | experimental | experimental |
| postgres_deploy | experimental | — | experimental | experimental | experimental |
| postgres_destroy | experimental | — | experimental | experimental | experimental |
| postgres_ops | experimental | — | experimental | experimental | experimental |
| postgres_preflight | experimental | — | experimental | experimental | not-applicable |
| postgres_upgrade | experimental | — | experimental | experimental | experimental |
| postgres_validate | experimental | — | experimental | experimental | not-applicable |
| prometheus_deploy | experimental | — | experimental | experimental | experimental |
| rsyslog | experimental | — | experimental | experimental | experimental |
| rsyslog_backup_restore | experimental | — | experimental | experimental | experimental |
| rsyslog_config | experimental | — | experimental | experimental | experimental |
| rsyslog_deploy | experimental | — | experimental | experimental | experimental |
| rsyslog_destroy | experimental | — | experimental | experimental | experimental |
| rsyslog_ops | experimental | — | experimental | experimental | experimental |
| rsyslog_preflight | experimental | — | experimental | experimental | not-applicable |
| rsyslog_upgrade | experimental | — | experimental | experimental | experimental |
| rsyslog_validate | experimental | — | experimental | experimental | not-applicable |
| samba | experimental | — | experimental | experimental | experimental |
| samba_backup_restore | experimental | — | experimental | experimental | experimental |
| samba_config | experimental | — | experimental | experimental | experimental |
| samba_deploy | experimental | — | experimental | experimental | experimental |
| samba_destroy | experimental | — | experimental | experimental | experimental |
| samba_ops | experimental | — | experimental | experimental | experimental |
| samba_preflight | experimental | — | experimental | experimental | not-applicable |
| samba_upgrade | experimental | — | experimental | experimental | experimental |
| samba_validate | experimental | — | experimental | experimental | not-applicable |
| semaphore_cac | experimental | — | experimental | experimental | experimental |
| semaphore_deploy | experimental | — | experimental | experimental | experimental |
| vault_backup_restore | experimental | — | experimental | experimental | experimental |
| vault_bootstrap | experimental | — | experimental | experimental | experimental |
| vault_config | experimental | — | experimental | experimental | experimental |
| vault_deploy | experimental | — | experimental | experimental | experimental |
| vault_foundational | experimental | — | experimental | experimental | not-applicable |
| vault_ops | experimental | — | experimental | experimental | experimental |
| vault_raft_snapshot | experimental | — | experimental | experimental | experimental |
| vault_scoped_approle | experimental | — | experimental | experimental | experimental |
| vault_secret_bundle | experimental | — | experimental | experimental | experimental |
| vault_validate | experimental | — | experimental | experimental | not-applicable |

<!-- role-coverage-table:end -->

<!-- END LIT_COMPATIBILITY_MATRIX -->

## Release Evidence

Releases produced by the enterprise role-quality workflow include immutable
evidence attached to the corresponding GitHub Release. Historical releases are
not retroactively described as having evidence they did not produce.
The evidence records:

- tested matrix combinations
- GitHub Actions run links
- artifact references
- publish status
- security scan status

See [GitHub Releases](https://github.com/lightning-it/ansible-collection-supplementary/releases),
[RELEASE.md](./RELEASE.md), and [TESTING.md](./TESTING.md) for the release process and validation model.
