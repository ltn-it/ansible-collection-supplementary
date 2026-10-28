# vault_config

Configure HashiCorp Vault (policies, PKI, AppRoles, secrets). This role is
platform-agnostic and assumes Vault is already reachable.

## Requirements

None.

## Variables

Required for configuration:

- `vault_config_url`
- `vault_config_terraform_source`

Token handling:

- `vault_config_token` (required effective token)
- `vault_config_vault_token` (preferred day-2 operational token input)

An explicit operational token is preferred over `vault_config_init.root_token`, so a revoked
initial root token in long-lived escrow cannot override valid day-2 credentials. If no operational
token is available, a newly initialized Vault still hands its root token directly from
`vault_bootstrap_init_payload`/`vault_bootstrap_token` into the first configuration run.

API TLS verification is enabled by default. `vault_config_api_ca_cert_path` is the absolute
CA path on `vault_config_api_delegate_to`; it inherits the controller-accessible path prepared by
`vault_deploy`. The role applies it to URI checks and every `community.hashi_vault` request.

See `roles/vault_config/defaults/main.yml` for shared variables.

Terraform state migration:

- Terragrunt writes local state on the controller under `vault_config_terraform_state_dir_local`
  (default `/tmp/vault/bootstrap`) and the tfstate files are copied to
  `/srv/vault/bootstrap` on the target.
- If MinIO tfstate backend facts are available, the role migrates local state to S3
  and removes the local files; otherwise it appends the controller-local state
  directory to `tfstate_pending_dirs` for later migration by `minio_bootstrap`.
- Migration tasks are tagged `tfstate` and `tfstate_migrate` so operators can run
  or skip them without changing the playbook.

## Dependencies

None.

## Example Playbook

```yaml
- name: Configure Vault
  hosts: vault_hosts
  gather_facts: false
  roles:
    - role: vault_config
  tags:
    - vault
```

## License

MIT

## Author

Lightning IT

## AppRole credentials

With `vault_config_manage_approle_credentials: true`, after Terraform configures
AppRole roles, Ansible creates missing Secret IDs and
stores them with the current Role ID in the configured KV v2 credential path.
The backend key resolves through `vault_config_auth_backends`; the default key is
`global_approle`. KV mount and path defaults match the Terraform template.
Entries marked `absent` are skipped. API calls use the role's controller delegate,
CA trust and authentication selection. Complete controller AppRole credentials
are preferred when AppRole authentication is configured; otherwise the
configuration token is used. Controller AppRole login occurs once per managed
entry, using `ansible_hashi_vault_mount_point` (default `approle`). The managed
Secret ID itself is only looked up. The authenticated token needs read access to the role ID and
KV entry, update access to Secret-ID lookup/creation, and KV create/update access.

Lookup does not log in with the managed Secret ID and does not consume its uses.
A valid Secret ID is reused; missing or expired credentials are replaced. Errors
such as denied access stop the run without rotating credentials. KV updates retain
other fields and use the read version for compare-and-set protection. Secret-ID
TTL and use limits come from the AppRole configured by Terraform. Check mode
skips credential creation with the Terraform apply block.

Credential management is disabled by default to preserve existing Terraform
ownership. Apply the [Terraform KV handoff](https://github.com/ltn-it/terraform-vault-instance/pull/383)
without destroying the stored entry before enabling this path. A Terraform
resource that continues to read or write that KV entry can overwrite the Secret
ID and capture it during state refresh. Historic state backups containing old
credentials require separate operator-controlled retirement and rotation.
