"""Hosted-only bounded pinned EE pre-pull before any courier bearer export."""

import json
import os
import subprocess
import sys
import time

IMAGE = (
    "quay.io/l-it/ee-wunder-devtools-ubi9:v1.18.2@sha256:"
    "58955457d3410706520f34fa7ea9823d5650aa4844c562cd5c0107024d825711"
)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


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
        message = result.stdout.decode("utf-8", "replace").lower()
        known_eof = "quay.io" in message and (
            "unexpected eof" in message
            or "tls handshake: eof" in message
            or "tls handshake eof" in message
            or '": eof' in message
        )
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
