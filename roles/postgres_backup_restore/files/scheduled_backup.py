#!/usr/bin/python3
"""Create private, atomic PostgreSQL backup sets using an existing rootless pod."""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

SCHEMA = "lit.postgres_backup_restore/v1"
SET_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{12}$")
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")
IMAGE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")
FILES = {"database.dump", "roles.sql", "manifest.json", "SHA256SUMS"}
FIELDS = {
    "instance",
    "container",
    "database",
    "username",
    "backup_dir",
    "pgdata_dir",
    "pgdata_mount",
    "socket_dir",
    "socket_port",
    "image",
    "uid",
    "home",
    "retention_days",
    "min_free_percent",
    "timeout_seconds",
    "max_age_seconds",
    "source_revision",
    "podman_binary",
}
# The deployed helper also supports the RHEL 9 system Python (3.9).
UTC = datetime.timezone(datetime.timedelta())


class Failure(Exception):
    """A static diagnostic category; never retain child process output."""


def require(condition, category):
    if not condition:
        raise Failure(category)


def utc_now():
    return datetime.datetime.now(UTC)


def stamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stamp(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def private_file(path, owners):
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata.st_uid in owners
        and not metadata.st_mode & 0o022,
        "unsafe_file",
    )
    return metadata


def read_json(path, owners):
    private_file(path, owners)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8") as stream:
        return json.load(stream)


def validate_config(config):
    require(isinstance(config, dict) and set(config) == FIELDS, "config_schema")
    for key in ("instance", "database", "username"):
        require(isinstance(config[key], str) and IDENTIFIER.fullmatch(config[key]), "identifier")
    require(
        isinstance(config["container"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", config["container"]),
        "container",
    )
    for key in ("backup_dir", "pgdata_dir", "pgdata_mount", "socket_dir", "home", "podman_binary"):
        value = config[key]
        require(isinstance(value, str) and re.fullmatch(r"/[A-Za-z0-9_./-]+", value), "path")
        require(str(Path(value)) == value and ".." not in Path(value).parts, "path")
    require(config["backup_dir"] != "/" and config["pgdata_dir"] != "/", "path")
    backup = Path(config["backup_dir"])
    data = Path(config["pgdata_dir"])
    require(backup != data and data not in backup.parents and backup not in data.parents, "pgdata_overlap")
    limits = {
        "uid": (1, 2147483647),
        "retention_days": (1, 3650),
        "min_free_percent": (0, 90),
        "timeout_seconds": (30, 86400),
        "max_age_seconds": (1, 31536000),
        "socket_port": (1, 65535),
    }
    for key, (minimum, maximum) in limits.items():
        require(type(config[key]) is int and minimum <= config[key] <= maximum, "numeric_config")
    require(isinstance(config["image"], str) and IMAGE.fullmatch(config["image"]), "image_pin")
    require(
        isinstance(config["source_revision"], str) and re.fullmatch(r"[0-9a-f]{40}", config["source_revision"]),
        "source_revision",
    )
    return config


def no_symlink_path(path):
    for parent in reversed((path,) + tuple(path.parents)):
        require(not parent.is_symlink(), "symlink_path")


def check_root(config):
    require(os.geteuid() == config["uid"], "runtime_uid")
    root = Path(config["backup_dir"])
    no_symlink_path(root)
    no_symlink_path(Path(config["pgdata_dir"]))
    metadata = root.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == config["uid"] and stat.S_IMODE(metadata.st_mode) == 0o700,
        "backup_permissions",
    )
    return root


def fsync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_bytes(path, content):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def atomic_json(path, content):
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        write_bytes(temporary, (json.dumps(content, sort_keys=True) + "\n").encode())
        os.replace(str(temporary), str(path))
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


class Commands:
    def __init__(self, config):
        self.config = config
        self.deadline = time.monotonic() + config["timeout_seconds"]
        self.environment = {
            "HOME": config["home"],
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "XDG_RUNTIME_DIR": "/run/user/" + str(config["uid"]),
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/" + str(config["uid"]) + "/bus",
        }

    def run(self, arguments, category, output=None, input_stream=None):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "timeout")
        try:
            # No shell: the trusted config pins the binary; argv is built from validated fields.
            result = subprocess.run(  # noqa: S603
                [self.config["podman_binary"]] + arguments,
                stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
                stdout=output if output is not None else subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=remaining,
                env=self.environment,
                cwd=self.config["home"],
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise Failure(category) from None
        require(result.returncode == 0, category)
        # A zero exit with warnings needs operator review, not silent acceptance.
        require(not result.stderr.strip(), category + "_warning")
        return result.stdout

    def stream_run(self, arguments, category, output):
        """Bound memory and stop this writer before consuming the free-space reserve."""
        try:
            # Same validated argv boundary as run(); never interpolate a command string.
            process = subprocess.Popen(  # noqa: S603
                [self.config["podman_binary"]] + arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.environment,
                cwd=self.config["home"],
            )
        except OSError:
            raise Failure(category) from None
        try:
            with selectors.DefaultSelector() as reader:
                reader.register(process.stdout, selectors.EVENT_READ, "data")
                reader.register(process.stderr, selectors.EVENT_READ, "diagnostic")
                while reader.get_map():
                    remaining = self.deadline - time.monotonic()
                    require(remaining > 0, "timeout")
                    for key, _ in reader.select(min(1, remaining)):
                        data = os.read(key.fileobj.fileno(), 1024 * 1024)
                        if not data:
                            reader.unregister(key.fileobj)
                            continue
                        require(key.data == "data", category + "_warning")
                        filesystem = os.statvfs(self.config["backup_dir"])
                        total = filesystem.f_blocks * filesystem.f_frsize
                        available = filesystem.f_bavail * filesystem.f_frsize
                        reserve = (total * self.config["min_free_percent"] + 99) // 100
                        require(available - len(data) - 1024 * 1024 >= reserve, "free_space")
                        output.write(data)
            remaining = self.deadline - time.monotonic()
            require(remaining > 0, "timeout")
            require(process.wait(timeout=remaining) == 0, category)
        except (OSError, subprocess.TimeoutExpired):
            raise Failure(category) from None
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def client(self, arguments, category, output=None, input_stream=None, stream_output=False):
        config = self.config
        options = [
            "exec",
            "-i",
            "--env",
            "PGHOST=" + config["socket_dir"],
            "--env",
            "PGPORT=" + str(config["socket_port"]),
            "--env",
            "PGDATABASE=" + config["database"],
            "--env",
            # A path below the null device cannot exist. /dev/null itself emits
            # a libpq warning because it is not a regular password file.
            "PGPASSFILE=/dev/null/lit-postgres-no-password",
            config["container"],
            "env",
            "-u",
            "PGPASSWORD",
            "-u",
            "PGSERVICE",
            "-u",
            "PGSERVICEFILE",
        ]
        if stream_output:
            return self.stream_run(options + arguments, category, output)
        return self.run(options + arguments, category, output, input_stream)

    def inspect(self):
        prefix = ["inspect", "--type", "container", "--format"]
        container = self.config["container"]
        running = self.run(prefix + ["{{.State.Running}}", container], "container_state")
        require(running.strip() == b"true", "container_stopped")
        image = self.run(prefix + ["{{.ImageName}}", container], "container_image").decode().strip()
        require(image == self.config["image"], "image_mismatch")
        mounts = json.loads(self.run(prefix + ["{{json .Mounts}}", container], "container_mounts"))
        require(
            any(
                mount.get("Type") == "bind"
                and mount.get("Source") == self.config["pgdata_dir"]
                and mount.get("Destination") == self.config["pgdata_mount"]
                for mount in mounts
            ),
            "pgdata_mount_mismatch",
        )


def normalized_roles(raw):
    lines = raw.splitlines(keepends=True)
    begin = [
        (index, re.fullmatch(rb"\\restrict ([A-Za-z0-9]+)\r?\n?", line))
        for index, line in enumerate(lines)
        if line.startswith(b"\\restrict ")
    ]
    end = [
        (index, re.fullmatch(rb"\\unrestrict ([A-Za-z0-9]+)\r?\n?", line))
        for index, line in enumerate(lines)
        if line.startswith(b"\\unrestrict ")
    ]
    if not begin and not end:
        return raw
    require(len(begin) == len(end) == 1 and begin[0][1] and end[0][1], "roles_guards")
    require(begin[0][0] < end[0][0] and begin[0][1][1] == end[0][1][1], "roles_guards")
    # Compare every SQL byte; normalize only pg_dumpall's paired random psql guard.
    return b"".join(line for index, line in enumerate(lines) if index not in (begin[0][0], end[0][0]))


def checked_manifest(directory, config, expected_id=None):
    set_id = directory.name if expected_id is None else expected_id
    require(SET_ID.fullmatch(set_id), "set_name")
    require(directory.name == (set_id if expected_id is None else set_id + ".partial"), "set_name")
    require(not directory.is_symlink() and directory.is_dir(), "set_directory")
    metadata = directory.stat()
    require(metadata.st_uid == config["uid"] and stat.S_IMODE(metadata.st_mode) == 0o700, "set_permissions")
    require({path.name for path in directory.iterdir()} == FILES, "set_files")
    for name in FILES:
        info = private_file(directory / name, {config["uid"]})
        require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_size > 0, "set_file")
    manifest = read_json(directory / "manifest.json", {config["uid"]})
    require(
        manifest["schema"] == SCHEMA
        and manifest["set_id"] == set_id
        and manifest["instance"] == config["instance"]
        and manifest["database"] == config["database"]
        and manifest["kind"] in ("manual", "scheduled"),
        "manifest",
    )
    parse_stamp(manifest["snapshot_utc"])
    sums = (directory / "SHA256SUMS").read_text().splitlines()
    expected = re.compile(r"^([0-9a-f]{64})  (database\.dump|roles\.sql|manifest\.json)$")
    parsed = [expected.fullmatch(line) for line in sums]
    require(len(parsed) == 3 and all(parsed), "checksum_manifest")
    checksums = {match[2]: match[1] for match in parsed}
    require(
        set(checksums) == {"database.dump", "roles.sql", "manifest.json"}
        and checksums["manifest.json"] == digest(directory / "manifest.json"),
        "manifest_checksum",
    )
    return manifest, checksums


def verify_set(directory, config, expected_id=None):
    manifest, checksums = checked_manifest(directory, config, expected_id)
    require(all(digest(directory / name) == expected for name, expected in checksums.items()), "checksum")
    return manifest


def prune(root, config, now, keep):
    require(shutil.rmtree.avoids_symlink_attacks, "retention_platform")
    cutoff = now - datetime.timedelta(days=config["retention_days"])
    removed = 0
    for directory in root.iterdir():
        if directory.name == keep or not SET_ID.fullmatch(directory.name):
            continue
        try:
            manifest = verify_set(directory, config)
            expired = parse_stamp(manifest["snapshot_utc"]) < cutoff
            scheduled = manifest["kind"] == "scheduled"
        except (Failure, OSError, ValueError, KeyError, TypeError):
            # Foreign, modified or malformed material is never a deletion candidate.
            continue
        if scheduled and expired:
            shutil.rmtree(directory)
            removed += 1
    fsync_directory(root)
    return removed


def create_set(root, config, kind):
    commands = Commands(config)
    commands.inspect()
    filesystem = os.statvfs(str(root))
    require(
        filesystem.f_blocks > 0 and 100 * filesystem.f_bavail >= config["min_free_percent"] * filesystem.f_blocks,
        "free_space",
    )
    roles_command = [
        "pg_dumpall",
        "--roles-only",
        "--no-role-passwords",
        "--no-password",
        "--username=" + config["username"],
    ]
    roles_before = commands.client(roles_command, "roles_before")
    require(normalized_roles(roles_before), "empty_roles")
    started = utc_now()
    set_id = started.strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12]
    staging = root / (set_id + ".partial")
    staging.mkdir(mode=0o700)
    dump = staging / "database.dump"
    fd = os.open(str(dump), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        commands.client(
            [
                "pg_dump",
                "--format=custom",
                "--no-password",
                "--username=" + config["username"],
                "--dbname=" + config["database"],
            ],
            "dump",
            stream,
            stream_output=True,
        )
        stream.flush()
        os.fsync(stream.fileno())
    require(dump.stat().st_size > 0, "empty_dump")
    roles_after = commands.client(roles_command, "roles_after")
    require(normalized_roles(roles_before) == normalized_roles(roles_after), "roles_changed")
    write_bytes(staging / "roles.sql", roles_before)
    with dump.open("rb") as stream:
        commands.client(["pg_restore", "--list"], "archive", subprocess.DEVNULL, stream)
    version = commands.client(["pg_dump", "--version"], "version").decode().strip()
    manifest = {
        "schema": SCHEMA,
        "set_id": set_id,
        "instance": config["instance"],
        "database": config["database"],
        "username": config["username"],
        "kind": kind,
        "snapshot_utc": stamp(started),
        "completed_utc": stamp(utc_now()),
        "source_revision": config["source_revision"],
        "image": config["image"],
        "pg_dump_version": version,
        "worker_sha256": digest(Path(__file__)),
    }
    write_bytes(staging / "manifest.json", (json.dumps(manifest, sort_keys=True) + "\n").encode())
    sums = "".join(
        digest(staging / name) + "  " + name + "\n" for name in ("database.dump", "roles.sql", "manifest.json")
    )
    write_bytes(staging / "SHA256SUMS", sums.encode())
    fsync_directory(staging)
    verify_set(staging, config, set_id)
    complete = root / set_id
    require(not complete.exists(), "set_collision")
    staging.rename(complete)
    fsync_directory(root)
    checked_manifest(complete, config)
    atomic_json(
        root / "last-success.json",
        {
            "set_id": set_id,
            "snapshot_utc": manifest["snapshot_utc"],
            "schema": SCHEMA,
        },
    )
    removed = prune(root, config, utc_now(), set_id) if kind == "scheduled" else 0
    return set_id, removed


def run_backup(config, kind):
    root = check_root(config)
    lock_path = root / ".lock"
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        require(stat.S_IMODE(private_file(lock_path, {config["uid"]}).st_mode) == 0o600, "lock_permissions")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("BACKUP_BUSY")
            return 75
        atomic_json(root / "last-run.json", {"status": "running", "started_utc": stamp(utc_now())})
        try:
            set_id, removed = create_set(root, config, kind)
        except Exception:
            atomic_json(root / "last-run.json", {"status": "failed", "finished_utc": stamp(utc_now())})
            raise
        atomic_json(
            root / "last-run.json",
            {
                "status": "ok",
                "set_id": set_id,
                "finished_utc": stamp(utc_now()),
                "pruned": removed,
            },
        )
        print("BACKUP_COMPLETED " + set_id)
        return 0


def status_backup(config):
    root = check_root(config)
    last = read_json(root / "last-success.json", {config["uid"]})
    require(last.get("schema") == SCHEMA and SET_ID.fullmatch(last["set_id"]), "last_success")
    manifest, _ = checked_manifest(root / last["set_id"], config)
    require(last["snapshot_utc"] == manifest["snapshot_utc"], "last_success")
    age = (utc_now() - parse_stamp(manifest["snapshot_utc"])).total_seconds()
    run = read_json(root / "last-run.json", {config["uid"]})
    require(age >= 0 and age <= config["max_age_seconds"] and run["status"] != "failed", "backup_unhealthy")
    print("BACKUP_STATUS_OK")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--status", action="store_true")
    mode.add_argument("--validate", action="store_true")
    mode.add_argument("--verify-set", metavar="SET_ID")
    parser.add_argument("--kind", choices=("manual", "scheduled"), default="manual")
    args = parser.parse_args()
    config = validate_config(read_json(Path(args.config), {0, os.geteuid()}))
    if args.validate:
        print("BACKUP_CONFIG_VALID")
        return 0
    if args.status:
        return status_backup(config)
    if args.verify_set:
        require(SET_ID.fullmatch(args.verify_set), "set_name")
        root = check_root(config)
        verify_set(root / args.verify_set, config)
        print("BACKUP_SET_VERIFIED")
        return 0
    return run_backup(config, args.kind)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Child stderr and Python exceptions can contain protected database details.
        print("BACKUP_FAILED; inspect protected service state; no database output logged", file=sys.stderr)
        sys.exit(2)
