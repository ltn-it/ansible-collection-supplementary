# nginx_deploy

Deploy Nginx from a rendered Kubernetes YAML manifest. Persistent lifecycle is
owned exclusively by a native Quadlet `.kube` unit through
`lit.foundational.podman_systemd`; direct kubeplay is limited to an explicit
non-systemd mode.

## Requirements

None.

## Variables

See `roles/nginx_deploy/defaults/main.yml`.

Key variables:
- `nginx_deploy_image`
- `nginx_deploy_pod_manifest_path`
- `nginx_deploy_host_conf_dir`
- `nginx_deploy_host_root`
- `nginx_deploy_listen_port`
- `nginx_deploy_tls_listen_port`
- `nginx_deploy_port_bindings`
- `nginx_deploy_networks` (native Quadlet `Network=` entries)
- `nginx_deploy_manage_default_site`
- `nginx_deploy_manage_systemd`
- `nginx_deploy_systemd_unit_name`
- `nginx_deploy_systemd_scope` (`system`, or explicit experimental `user`)
- `nginx_deploy_quadlet_dir`
- `nginx_deploy_systemd_enabled` (must remain `true` for generated Quadlet services)
- `nginx_deploy_selinux_relabel`
- `nginx_deploy_skip_runtime`

Set `nginx_deploy_networks` to the private application network when NGINX is
the exclusive ingress and reaches backends through Podman DNS names. Persistent
start, stop, restart and removal remain owned by the native Quadlet unit.
The default native unit is `<pod-name>-pod.service`, avoiding collisions with
an administrator-managed `nginx.service`. Enabling systemd management without
a detected systemd service manager fails during prechecks.
Changes that would restart an already existing native Quadlet fail closed until
transactional manifest backup and restore support is available.
Managed-systemd mode rejects `nginx_deploy_systemd_enabled: false` because the
generated Quadlet unit cannot converge to a durable disabled state.

### Rootless user scope (experimental)

Set `nginx_deploy_systemd_scope: user` explicitly to use native User Quadlets.
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

- `lit.foundational.kubeplay`
- `lit.foundational.podman_systemd`

## Example Playbook

```yaml
- name: Deploy Nginx
  hosts: web
  gather_facts: true
  roles:
    - role: nginx_deploy
  tags:
    - nginx
```

## License

MIT

## Author

Lightning IT

User-scope candidate validation requires `/bin/sh` and `getent ahostsv4` in the Nginx image. It resolves the upstream on the actual private network and binds the sorted IPv4 address set to the applied identity, so an unchanged hostname moving to a different address forces reconciliation.

The experimental user-scope edge owns and validates its complete generated configuration. It rejects skipped configuration/validation, disabled configuration tests, disabled default-site management and unsupported extra HTTP/server directives before managed writes. Runtime-only reconciliation of caller-managed proxy rules is not supported by this profile.
