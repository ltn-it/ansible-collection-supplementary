"""Hosted-only bounded pinned EE pre-pull before any courier bearer export."""

import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

IMAGE = "quay.io/l-it/ee-wunder-devtools-ubi9:v1.18.2@sha256:58955457d3410706520f34fa7ea9823d5650aa4844c562cd5c0107024d825711"  # noqa: E501 -- Keep the immutable image visible to source inventory.


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def retryable_registry_eof(raw):
    message = raw.decode("utf-8", "replace").lower()
    if any(word in message for word in ("unauthorized", "forbidden", "access denied", "not found")):
        return False
    # Match the observed Docker short-read diagnostic for the fixed image.
    short_read = re.compile(r"(?:docker: )?short read: expected [0-9]+ bytes but got [0-9]+: unexpected eof")
    observed_short_read = any(short_read.fullmatch(line.strip()) for line in message.splitlines())
    addresses = re.findall(r"https?://[^\s\"']+", message)
    if not addresses:
        return observed_short_read
    try:
        for address in addresses:
            parsed = urlsplit(address)
            if (
                parsed.scheme != "https"
                or parsed.hostname != "quay.io"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port not in (None, 443)
            ):
                return False
    except ValueError:
        return False
    endings = ("unexpected eof", "tls handshake: eof", "tls handshake eof", ": eof")
    return any(line.strip().rstrip('"').endswith(endings) for line in message.splitlines())


def prepare():
    deadline = time.monotonic() + 600
    env = {"PATH": os.environ["PATH"], "HOME": os.environ["RUNNER_TEMP"], "LANG": "C", "LC_ALL": "C"}
    for attempt in range(1, 4):
        remaining = deadline - time.monotonic()
        need(remaining > 0, "courier-ee-pull-deadline")
        result = subprocess.run(  # noqa: S603 -- Fixed Docker command and pinned public image.
            ["docker", "pull", "--platform=linux/amd64", IMAGE],  # noqa: S607 -- Trusted hosted runner PATH.
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=remaining,
            env=env,
        )
        need(len(result.stdout) <= 2 * 1024**2, "courier-ee-pull-output-bound")
        if result.returncode == 0:
            print(json.dumps({"state": "PINNED_COURIER_EE_PREPULLED", "attempts": attempt}))
            return
        known_eof = retryable_registry_eof(result.stdout)
        need(known_eof and attempt < 3, "courier-ee-pull-unknown-or-exhausted")
        remaining = deadline - time.monotonic()
        need(remaining > 1, "courier-ee-pull-deadline")
        time.sleep(1)
    raise ValueError("courier-ee-pull-exhausted")


if __name__ == "__main__":
    try:
        need(len(sys.argv) == 1, "courier-ee-pull-arguments")
        prepare()
    except Exception as error:
        print(
            json.dumps(
                {
                    "state": "COURIER_PREPULL_HELD",
                    "category": str(error) if type(error) is ValueError else type(error).__name__,
                }
            )
        )
        raise SystemExit(2) from None
