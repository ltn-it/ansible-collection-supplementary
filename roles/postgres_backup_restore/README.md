# postgres_backup_restore

Back up and restore PostgreSQL databases. One-shot operations stay disabled unless
`postgres_backup_restore_execute=true`. The opt-in `schedule` action manages a
rootless Podman backup worker and user systemd timer.

The role is **experimental**. [Role coverage](../../meta/role-coverage.yml) owns
platform and Tiny/Heavy/Application Acceptance dispositions. Fixture tests alone
do not prove a working runtime or restore.

## Requirements

Consume the collection's Ansible baseline in
[meta/runtime.yml](../../meta/runtime.yml).

Scheduling requires Linux, Python 3.9 or later, an existing non-root application
account with a persistent systemd user manager, and an already running,
digest-pinned Podman PostgreSQL container. The container must provide `pg_dump`,
`pg_dumpall`, `pg_restore` and `env -u`, and authorize the configured existing user over its
local Unix socket. OS preparation and database lifecycle remain with their
owning roles; this role never changes packages, accounts, lingering, system
timezone or PostgreSQL authentication.

Use a private directory outside PGDATA. Symlinked paths, unexpected owners and
existing non-private backup directories fail closed.

## Variables

[defaults/main.yml](defaults/main.yml) contains the complete interface.

The existing actions are `none`, `backup` and `restore`; `schedule` is additive.
One-shot behavior, password input and explicit `YES_RESTORE` confirmation remain
unchanged. Scheduling requires `postgres_backup_restore_execute=true`,
`postgres_backup_restore_format=custom` and
`postgres_backup_restore_execution_mode=podman`.

Provide the existing `postgres_backup_restore_backup_dir`, `db_name`, `db_user`
and `container_name` inputs. All scheduling inputs have the full
`postgres_backup_restore_schedule_` prefix:

- `instance`: unique safe identifier.
- `user`, `group`, `uid`, `home`: exact prepared application-account mapping.
- `pgdata_dir`, `pgdata_mount`: expected host bind source and container destination.
- `image`: exact existing image reference with `@sha256:`.
- `source_revision`: full source commit of the installed collection.
- `calendar`: systemd calendars including the intended timezone.
- `retention_days`: completed scheduled-set age, default 14 days.
- `min_free_percent`: reserve checked before and during streaming, default 20.
- `timeout_seconds`: total command deadline, default 1800 seconds.
- `max_age_seconds`: local snapshot-age threshold for the status check.
- `after`: optional service ordering; never starts a stopped database.
- `enabled`: timer enable/start gate, default `false`.
- `state`: `present` or `absent`; removal preserves all backup sets.

Scheduled sets contain the entire selected database, role definitions **without
passwords**, an immutable manifest and SHA-256 checksums. Role definitions are
compared before/after the dump. Only PostgreSQL's paired random psql guard lines
are normalized for comparison; the stored SQL remains unchanged. No fixed
`--restrict-key` is used. Rebuilding a role's password needs the existing secret
source; the role export does not contain password material.

Archive and set checksums are verified before atomic directory publication.
A `.partial` directory is never a ready backup. Failed attempts never prune old
sets. Only valid expired `scheduled` sets belonging to this instance/database
are eligible for retention. Manual restore points, unknown/modified material
and symlinks are preserved. Manual runs never trigger pruning. A concurrent
run returns exit 75 without altering the active operation.

The worker disables password prompts, password-file fallback and inherited
client credentials. It uses the configured Unix socket and never forwards a
database password. Child errors are captured without logging database output.
Restore SQL is privileged recovery input: only restore trusted verified sets
onto an explicitly selected isolated target.

The free-space guard limits this writer; other concurrent writers still require
capacity monitoring. No checksum/archive listing substitutes for a restore test.
There is no WAL/PITR, external transport, external-copy health, alarm delivery or
whole-host recovery implementation in this role.

## Dependencies

Scheduling introduces no new collection dependency. Prepared Podman, Python,
systemd user management and PostgreSQL clients are runtime prerequisites.
External backup and monitoring integration remain separate consumers.

## Example Playbook

The inventory supplies the `backup_*` values from its approved runtime and
immutable collection binding; no example image digest or commit is invented.
Initially leave the timer disabled, verify a manual set and its restore, then
explicitly enable the timer.

~~~yaml
---
- name: Configure a backup schedule for existing rootless PostgreSQL
  hosts: database_hosts
  become: true
  roles:
    - role: lit.supplementary.postgres_backup_restore
      postgres_backup_restore_action: schedule
      postgres_backup_restore_execute: true
      postgres_backup_restore_execution_mode: podman
      postgres_backup_restore_backup_dir: "{{ backup_directory }}"
      postgres_backup_restore_db_name: "{{ backup_database }}"
      postgres_backup_restore_db_user: "{{ backup_database_user }}"
      postgres_backup_restore_container_name: "{{ backup_container }}"
      postgres_backup_restore_schedule_instance: "{{ backup_instance }}"
      postgres_backup_restore_schedule_user: "{{ backup_application_user }}"
      postgres_backup_restore_schedule_group: "{{ backup_application_group }}"
      postgres_backup_restore_schedule_uid: "{{ backup_application_uid }}"
      postgres_backup_restore_schedule_home: "{{ backup_application_home }}"
      postgres_backup_restore_schedule_pgdata_dir: "{{ backup_pgdata }}"
      postgres_backup_restore_schedule_image: "{{ backup_postgres_image }}"
      postgres_backup_restore_schedule_source_revision: "{{ backup_collection_revision }}"
      postgres_backup_restore_schedule_calendar:
        - "*-*-* 00:00:00 UTC"
        - "*-*-* 12:00:00 UTC"
      postgres_backup_restore_schedule_enabled: false
~~~

Run the following under the application account after setting `BACKUP_INSTANCE`
to its configured identifier. The manual operation creates a non-prunable
restore point. The status command reads metadata only.

~~~bash
set -euo pipefail
test "$(id -u)" -ne 0
test -n "$BACKUP_INSTANCE"
python3 "/usr/local/libexec/lit-postgres-backup-$BACKUP_INSTANCE.py" \
  --config "/etc/lit-postgres-backup/$BACKUP_INSTANCE.json" --run --kind manual
python3 "/usr/local/libexec/lit-postgres-backup-$BACKUP_INSTANCE.py" \
  --config "/etc/lit-postgres-backup/$BACKUP_INSTANCE.json" --status
~~~

`--verify-set SET_ID` checks all saved file checksums. `--status` measures the
database snapshot age, not the later completion/copy time, and flags a failed
latest attempt. It does not certify an external copy. Success markers are
`BACKUP_COMPLETED`, `BACKUP_SET_VERIFIED` and `BACKUP_STATUS_OK`.

For rollback, set `postgres_backup_restore_schedule_state=absent`. Only the
instance's timer, service, worker and settings are removed. An active backup is
not killed: the timer is disabled and removal stops safely until that operation
finishes. Repeating removal is idempotent. Backup data always remains.

Local deterministic tests use the pinned Devtools:

~~~bash
WUNDER_DEVTOOLS_RUN_AS_HOST_UID=1 bash scripts/wunder-devtools-ee.sh \
  python3 -m unittest discover -s tests/unit -p test_postgres_scheduled_backup.py
~~~

This covers permissions, locking, publication, corruption, retention, snapshot
age and safe failure output with fixtures. Fresh package installation, actual
Podman/systemd, timer execution, idempotence and database/application recovery
need separate proof on an authorized isolated target before delivery. No new
supported Tiny/Heavy/Application Acceptance cell is claimed here. Public
profile orchestration stays in `modulix-validation`.

## License

MIT.

## Author

Lightning IT.
