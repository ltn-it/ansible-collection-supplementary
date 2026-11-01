"""Read-only admission for the current run, before release Environment access."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

MANDATORY = (
    "security-classification",
    "quality-matrix",
    "lint-sanity",
    "build-install",
    "role-coverage",
    "tiny",
    "heavy",
    "acceptance",
    "runtime-evidence",
    "evidence",
)
PENDING = {"", "pending", "queued", "waiting", "requested", "in_progress"}
REPORT = Path("artifacts/release-admission.json")


class StaleEvidenceError(ValueError):
    """Valid JSON belongs to a different producer tuple."""


def prerequisites(needs: dict[str, Any]) -> dict[str, Any]:
    results = {name: needs.get(name, {}).get("result", "") for name in MANDATORY}
    failures = {name: result for name, result in results.items() if result != "success"}
    return {
        "state": "pending"
        if failures and all(result in PENDING for result in failures.values())
        else "failed"
        if failures
        else "prerequisites-satisfied",
        "results": results,
        "unsatisfied": failures,
        "pending": {name: result for name, result in failures.items() if result in PENDING},
        "failed": {name: result for name, result in failures.items() if result not in PENDING},
        # Profile-cell skips are interpreted by the existing aggregate jobs.
        # A valid not-applicable profile still has a successful aggregate;
        # skipping a mandatory aggregate can never grant release admission.
        "profile_requirements": {
            name: needs.get("quality-matrix", {}).get("outputs", {}).get(name, "")
            for name in ("tiny_required", "heavy_required", "acceptance_required", "runtime_evidence_required")
        },
    }


def verify_identity(root: Path, expected: dict[str, str]) -> None:
    for relative in ("manifest.json", "security/provenance.json"):
        payload = json.loads((root / relative).read_text(encoding="utf-8"))
        for name, value in expected.items():
            if payload.get(name) != value:
                raise StaleEvidenceError(f"stale {relative}: {name} does not match the current run")


def main() -> int:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"state": "failed"}
    try:
        if sys.argv[1:] == ["prerequisites"]:
            report = prerequisites(json.loads(os.environ["NEEDS_JSON"]))
            accepted = report["state"] == "prerequisites-satisfied"
        elif sys.argv[1:] == ["artifacts"]:
            report = json.loads(REPORT.read_text(encoding="utf-8"))
            if report.get("state") != "prerequisites-satisfied":
                raise ValueError("mandatory prerequisites were not admitted")
            expected = {
                "repository": os.environ["GITHUB_REPOSITORY"],
                "commit_sha": os.environ["SOURCE_SHA"],
                "workflow_run_id": os.environ["GITHUB_RUN_ID"],
                "workflow_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            }
            report["expected"] = expected
            try:
                verify_identity(Path("artifacts/evidence"), expected)
            except StaleEvidenceError as error:
                report["state"] = "stale"
                report["error"] = str(error)
                accepted = False
            else:
                report["state"] = "identity-verified"
                accepted = True
        elif sys.argv[1:] == ["complete"]:
            report = json.loads(REPORT.read_text(encoding="utf-8"))
            if report.get("state") != "identity-verified":
                raise ValueError("current-run artifact identity was not verified")
            report["state"] = "admitted"
            accepted = True
        else:
            raise ValueError("expected prerequisites, artifacts or complete")
    except (KeyError, OSError, TypeError, ValueError, AttributeError) as error:
        report["state"] = "failed"
        report["error"] = str(error)
        accepted = False
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
