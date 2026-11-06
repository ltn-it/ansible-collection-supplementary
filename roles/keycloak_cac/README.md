# keycloak_cac

Configuration-as-Code orchestration role for Keycloak.

This role intentionally separates object/API orchestration concerns from runtime deployment
(`keycloak_deploy`), following the `_cac` role split used across the collection.

## Requirements

The target Keycloak service must be available. The canonical Heavy and
Application Acceptance scenarios deploy it with `keycloak_deploy`.

## Variables

See `roles/keycloak_cac/defaults/main.yml`.

Key variables:
- `keycloak_cac_skip_apply`
- `keycloak_cac_url`
- `keycloak_cac_realm`
- `keycloak_cac_admin_user`
- `keycloak_cac_admin_password`
- `keycloak_cac_samba_ldap_enabled`
- `keycloak_cac_samba_ldap_provider`
- `keycloak_cac_ldap_providers`
- `keycloak_cac_authentication_flows`
- `keycloak_cac_identity_providers`
- `keycloak_cac_required_actions`
- `keycloak_cac_realm_flow_bindings`

### Identity brokering (optional)

All broker catalogs default to empty lists. Flow/provider entries use the object parameters of
`community.general.keycloak_authentication` and
`community.general.keycloak_identity_provider`, respectively. Each entry must
specify a nonempty `realm` and `alias`; identity providers never implicitly
target `master`. Use canonical option names shown in the module documentation,
not aliases. API authentication and transport options belong to the role, not
individual entries. Unknown top-level options are rejected before API access.

Tasksets reconcile authentication flows before identity providers, so a
provider can reference a flow created in the same invocation. Realm creation
precedes both. Deletion reverses that dependency: remove referring providers
in one invocation before removing their flows in another. The catalog is not
an authoritative purge: omitted objects are not deleted.

`keycloak_cac_required_actions` accepts the `realm`, `state` and
`required_actions` parameters of `community.general.keycloak_authentication_required_actions`.
This permits consumers to disable application-initiated linking explicitly;
it does not by itself disable other account-linking routes.

`keycloak_cac_realm_flow_bindings` contains only `realm` and `browser_flow`.
Each realm must appear once as present in `keycloak_cac_realms`. Bindings run
after flows, providers and required actions, reusing direct realm
reconciliation. Do not set a not-yet-created browser flow in the
initial realm definition. Removing a binding does not restore a default flow.
Keep consumers disabled until the entire configuration is reconciled and
verified; task ordering is not an atomic activation transaction.

Avoid `force: true` for normal flow reconciliation: the underlying module
deletes and recreates an existing flow, so this is not idempotent and referring
providers must be handled first. In the pinned module, check mode can return
before comparing executions of an existing flow; a zero-change check-mode
result is not proof that the actual flow matches the requested executions.

The role does not choose an upstream IdP, create tier identities, or enforce
an environment-specific tier model. Consumers must define and test first-login
flows, account-link restrictions, session freshness, issuer/subject mapping,
entitlements and revocation before enabling access. Catalogs and API tasks
suppress secret-bearing output. Obtain any credentials from a protected secret
source; do not put them in plaintext inventory.

The new catalogs require real Keycloak apply/query/idempotency and login
acceptance evidence before production use; local contract tests alone are not
that evidence. Existing component profile coverage does not yet prove these
new brokering paths.

## Samba LDAPS user federation

Set `keycloak_cac_samba_ldap_enabled: true` to create a default Samba AD/LDAPS
LDAP provider in the target realm. Override `keycloak_cac_samba_ldap_provider`
for site-specific DNs, bind credentials, and connection URLs. Additional LDAP
providers can be supplied through `keycloak_cac_ldap_providers`.

## Dependencies

`community.general` provides the Keycloak API modules declared in `galaxy.yml`.

## Example Playbook

```yaml
- name: Validate Keycloak API preflight
  hosts: localhost
  gather_facts: false
  roles:
    - role: lit.supplementary.keycloak_cac
      vars:
        keycloak_cac_skip_apply: false
        keycloak_cac_url: http://127.0.0.1:8080
        keycloak_cac_realm: master
        keycloak_cac_admin_user: admin
        keycloak_cac_admin_password: "{{ vault_keycloak_admin_password }}"
```

## License

MIT

## Author

Lightning IT

## Enterprise test disposition

- Classification: configuration-as-code API orchestration.
- Maturity: production-supported through the registry-required Keycloak
  component profiles.
- Supported platform: Ubuntu 24.04. RHEL 9 and RHEL 10 remain candidates until
  their exact-commit matrices pass on approved images.
- Tiny: real realm, client, group, role, user, mapping, token, and idempotency
  reconciliation.
- Heavy: production-like deployment foundation, LDAP provider integration,
  persisted state, authentication, and negative credential checks.
- Application Acceptance: an independently reported apply, query, mutation,
  zero-change reconciliation, and deletion lifecycle, followed by browser and
  protected API behavior driven by reconciled identities and authorization
  state.
- Security: administrator, bind, and client credentials are ephemeral or
  supplied by a protected secret source and must never enter evidence.
- Evidence and commands: see
  [`docs/testing/keycloak.md`](../../docs/testing/keycloak.md).
- Limitations: the current suite does not claim complete deletion reconciliation
  for every supported Keycloak object type.
  Authentication-flow, identity-provider, required-action, and deferred-binding
  catalogs have real Tiny create, update, idempotency, and API-readback coverage;
  a complete upstream broker login and consumer acceptance remain unproven.
