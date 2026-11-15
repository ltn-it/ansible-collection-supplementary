# postgres_backup_restore

Back up and restore PostgreSQL databases. One-shot operations stay disabled unless
`postgres_backup_restore_execute=true`. The opt-in `schedule` action manages a
rootless Podman backup worker with a user systemd timer or daily cron trigger.

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
- `worker`: shared implementation path, default `/usr/local/libexec/postgres-backup.py`.
  Set `/usr/local/libexec/postgres-backup-keycloak.py` for Keycloak consumers;
  keep that path identical across hosts. Services, settings and schedules remain
  instance-specific. All consumers of a shared worker must use the same version.
- `user`, `group`, `uid`, `home`: exact prepared application-account mapping.
- `pgdata_dir`, `pgdata_mount`: expected host bind source and container destination.
- `image`: exact existing image reference with `@sha256:`.
- `source_revision`: full source commit of the installed collection.
- `backend`: `systemd` (default) or `cron`; both start the same user service.
- `calendar`: systemd calendars including the intended timezone.
- `cron_hour`, `cron_minute`: daily cron start time as integers (0–23 and 0–59).
- `cron_timezone`: explicit zoneinfo name, default `UTC`; no host timezone change.
- `retention_days`: completed scheduled-set age, default 14 days.
- `min_free_percent`: reserve checked before and during streaming, default 20.
- `timeout_seconds`: total command deadline, default 1800 seconds.
- `max_age_seconds`: local snapshot-age threshold for the status check.
- `after`: optional service ordering; never starts a stopped database.
- `enabled`: schedule enable gate, default `false`.
- `state`: `present` or `absent`; removal preserves all backup sets.
- `log_config`: retired experimental input; must remain empty. Nonempty values
  are rejected before configuring a schedule.

The scheduled service invokes the existing shared worker directly. It neither
installs nor invokes a component-log helper. Standard output/error currently
use the system journal. Component-wide RPM retention and backup/restore
operational-file integration remain separate consumer integration requirements;
the journal setting does not prove those limits. `KillMode=control-group`
contains worker descendants when stopping the service. Never route a database
dump stream or restored SQL into an operational log.

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
Retention inspects checked manifest metadata first and hashes payloads only for
expired scheduled deletion candidates, immediately before removal.
Numeric schedule limits accept integers or decimal integer strings; booleans,
fractions and malformed text are rejected before template conversion.
The same guard includes the runtime UID and socket port. UID-derived service and
command environment paths use the canonical integer value, including for text
inputs with leading zeroes.

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
The cron backend additionally requires an already running Cronie `crond.service`
with `CRON_TZ` support. It installs an instance-specific root-owned file under
`/etc/cron.d/` and disables the corresponding systemd timer. Switching to systemd
removes that cron file before enabling the timer. Cron does not catch up missed
runs after downtime; monitor the worker's snapshot age with `--status`.
The cron trigger starts the user service and sends no cron email. Without an
explicit log policy, worker diagnostics go to the existing journal. With capture
enabled they go to the shared component log; only service/collector diagnostics
remain in the platform journal. This role does not set a journal retention quota.
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
python3 /usr/local/libexec/postgres-backup.py \
  --config "/etc/postgres-backup/$BACKUP_INSTANCE.json" --run --kind manual
python3 /usr/local/libexec/postgres-backup.py \
  --config "/etc/postgres-backup/$BACKUP_INSTANCE.json" --status
~~~

`--verify-set SET_ID` checks all saved file checksums. `--status` measures the
database snapshot age, not the later completion/copy time, and flags a failed
latest attempt. It does not certify an external copy. Success markers are
`BACKUP_COMPLETED`, `BACKUP_SET_VERIFIED` and `BACKUP_STATUS_OK`.
A running attempt is healthy only while the backup lock is held and its age is
within the service deadline (configured timeout plus 60 seconds). An abandoned,
overdue or unknown last-run state is unhealthy even with a recent successful set.

For rollback, set `postgres_backup_restore_schedule_state=absent`. Only the
instance's cron trigger, timer, service and settings are removed. The shared
worker is retained for other instances. An active backup is
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

### Optional shared operational log

`postgres_backup_restore_operations_log_file` defaults to empty (journal).
An explicit `/var/log/postgres-backup/<instance>/operations.log` uses systemd's
`StandardOutput=append:` and inherited stderr; the shared worker is unchanged.
The role prepares a protected root-owned instance directory and a private file
owned by the existing backup account, without truncating content. Symlinked paths
and foreign existing files are rejected. This requires a systemd version supporting
`append:`. No capture helper, wrapper or extra service is installed.

The consumer must include this file in PostgreSQL's rotation/archive budget.
An existing open descriptor needs a compatible rotation strategy; `copytruncate`
has a record-loss window. Removing a schedule preserves operational logs.
Manual backup/restore actions use the same protected file when explicitly enabled:
quoted native database commands append stdout/stderr directly with UTC START/END
and exit status. Backup dump bytes remain in the backup file, never in the log.
Logged backups write to a fresh private temporary file in the destination
directory and atomically replace the destination only after a successful dump.
Existing hardlinks retain their old bytes; failed dumps preserve the prior
destination and remove the partial temporary file.
Client-mode custom restores retain the regular archive filename, including for
`--jobs` parallel restoration. Plain SQL and the existing Podman restore path
continue reading their input through stdin.
Plain SQL restores enforce ON_ERROR_STOP=1 so SQL errors fail the command.
Ansible hides command output unconditionally on this path. Podman receives the
password from the task environment rather than its command line. No installed
capture helper or daemon is used. The caller must supply the same existing account,
UID, home and PGDATA as for scheduled backups. Full database/SELinux/systemd and
concurrent rotation tests remain required; command fixtures do not prove restore.

### Existing application control

Before replacing a scheduled worker, the role checks the existing fapolicyd
service. With active application control, an unchanged worker must already match
the active path/size/SHA256 entry. A different or untrusted payload stops before
replacement unless both `postgres_backup_restore_schedule_fapolicyd_trust_file`
(a dedicated file under `/etc/fapolicyd/trust.d/`) and
`postgres_backup_restore_schedule_fapolicyd_approved_sha256` explicitly select
and approve the exact packaged worker. Both default to empty. The preflight can
be called separately with `tasks_from: schedule_worker_preflight` before other
setup mutations.

Admission manages only the single selected worker declaration, preserving other
trust files, global policy and service configuration. The existing service is
not enabled, restarted or made permissive. A bounded read-back verifies the
active entry. On installation/admission failure, previous worker/trust bytes
are restored from controller memory and declared trust is rechecked; a failed
recovery remains an error. No data backup is started by these steps. Removing
an instance schedule retains the shared worker and its admission.

Runtime UID values transported as decimal text, including leading zeroes, use
the canonical numeric UID in the JSON configuration, service, command environment
and Cron environment. Cron and systemd therefore address the same runtime
directory and user-manager bus.
