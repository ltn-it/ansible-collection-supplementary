"""Final evidence must join a genuine signature to independent native facts."""

import base64
import copy
import hashlib
import io
import json
import os
import unittest
import zipfile
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import g06_final_quality as final_quality
from scripts import quality_evidence
from scripts.g06_final_quality import (
    FinalQualityError,
    compare_provider_zip,
    verify_final_receipt,
    verify_physical_evidence,
)
from tests.unit import test_quality_evidence as evidence_fixtures


class FinalQualityTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public = public.hex()
        self.header = {"alg": "EdDSA", "typ": "lit-incus-final-quality+jwt", "kid": hashlib.sha256(public).hexdigest()}
        self.expected = {
            "repository": "ltn-it/ansible-collection-supplementary",
            "repository_id": 1103407173,
            "run_id": 1234,
            "run_attempt": 1,
            "source_sha": "a" * 40,
            "controller_sha": "b" * 40,
            "profile": "heavy",
            "scenario": "keycloak-heavy",
            "target": "ubuntu-24.04",
        }
        self.execution = {"job_id": 3456, "check_run_id": 4567, "conclusion": "success", "completed_at": 1000}
        self.artifact = {"id": 7890, "name": "quality-result-fixture", "digest_sha256": "c" * 64, "size_in_bytes": 4096}
        self.payload = {
            **self.expected,
            "schema": 1,
            "purpose": "urn:lightning-it:g06:final-quality:v1",
            "state": "closed",
            "lease_id": "fixture-owned-lease",
            "execution": self.execution,
            "artifact": self.artifact,
            "capture_receipt_sha256": "d" * 64,
            "cleanup": {
                "state": "verified",
                "ledger_sha256": "e" * 64,
                "closed_at": 1001,
                "resource_absence_sha256": "f" * 64,
            },
            "custody_policy_sha256": "1" * 64,
            "cell_sha256": "2" * 64,
            "engine_policy_sha256": "3" * 64,
            "signer_public_key_hex": self.public,
            "issued_at": 1002,
        }

    def envelope(self, payload=None):
        payload = payload if payload is not None else self.payload

        def segment(value):
            return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

        body = segment(self.header) + "." + segment(payload)
        signature = base64.urlsafe_b64encode(self.key.sign(body.encode())).decode().rstrip("=")
        return {"schema": 1, "receipt": payload, "signature": body + "." + signature}

    def verify(self, envelope, **changes):
        arguments = dict(
            public_key_hex=self.public,
            expected=self.expected,
            native_execution=self.execution,
            native_artifact=self.artifact,
        )
        arguments.update(changes)
        return verify_final_receipt(envelope, **arguments)

    def test_real_signature_and_exact_native_records_pass(self):
        self.assertEqual(self.verify(self.envelope()), self.payload)

    def test_independent_key_and_unsigned_payload_tamper_are_rejected(self):
        with self.assertRaises((FinalQualityError, InvalidSignature)):
            self.verify(self.envelope(), public_key_hex="0" * 64)
        envelope = self.envelope()
        envelope["receipt"] = {**self.payload, "source_sha": "4" * 40}
        with self.assertRaisesRegex(FinalQualityError, "signed payload"):
            self.verify(envelope)

    def test_signed_borrowed_identity_artifact_and_execution_are_rejected(self):
        for field, value in (
            ("run_id", 9999),
            ("source_sha", "4" * 40),
            ("controller_sha", "5" * 40),
            ("run_attempt", True),
        ):
            with self.subTest(field=field), self.assertRaises(FinalQualityError):
                self.verify(self.envelope({**self.payload, field: value}))
        for field in ("id", "digest_sha256", "size_in_bytes"):
            native = {**self.artifact, field: "6" * 64 if field == "digest_sha256" else 999}
            with self.subTest(artifact=field), self.assertRaises(FinalQualityError):
                self.verify(self.envelope(), native_artifact=native)
        with self.assertRaises(FinalQualityError):
            self.verify(self.envelope(), native_execution={**self.execution, "job_id": 9999})

    def test_wrong_signature_and_other_signing_purpose_are_rejected(self):
        self.key = Ed25519PrivateKey.generate()
        with self.assertRaises(InvalidSignature):
            self.verify(self.envelope())
        self.header["typ"] = "lit-incus-context+jwt"
        with self.assertRaisesRegex(FinalQualityError, "signing domain"):
            self.verify(self.envelope())

    def test_signed_pending_failed_or_early_cleanup_can_never_pass(self):
        cases = [
            {"state": "pending"},
            {"issued_at": 999},
            {"cleanup": {**self.payload["cleanup"], "closed_at": 999}},
            {"cleanup": {**self.payload["cleanup"], "state": "pending"}},
            {"capture_receipt_sha256": "missing"},
        ]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(FinalQualityError):
                self.verify(self.envelope({**self.payload, **change}))
        failed = copy.deepcopy(self.execution)
        failed["conclusion"] = "failure"
        with self.assertRaises(FinalQualityError):
            self.verify(self.envelope({**self.payload, "execution": failed}), native_execution=failed)

    def physical_fixture(self):
        fixture = evidence_fixtures.QualityEvidenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        registry = fixture._registry()
        coverage = json.loads(registry.read_text())
        coverage["roles"]["demo_role"].update(tiny="not-applicable", heavy="supported")
        coverage["scenarios"]["demo-heavy"] = coverage["scenarios"].pop("demo-tiny")
        coverage["scenarios"]["demo-heavy"]["profile"] = "heavy"
        registry.write_text(json.dumps(coverage))
        junit = fixture._junit()
        junit.write_text(
            junit.read_text()
            .replace('name="run_attempt" value="2"', 'name="run_attempt" value="1"')
            .replace('name="profile" value="tiny"', 'name="profile" value="heavy"')
            .replace("demo-tiny", "demo-heavy")
        )
        environment = {
            **fixture._environment(),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": self.expected["repository"],
        }
        with patch.dict(os.environ, environment, clear=False):
            self.assertEqual(
                quality_evidence.assemble(
                    fixture.evidence_root,
                    input_roots=[fixture.artifacts],
                    registry_path=registry,
                    repository_root=fixture.repository,
                    preliminary=True,
                ),
                0,
            )
        self.expected.update(profile="heavy", scenario="demo-heavy")
        self.payload.update(self.expected)
        self.artifact["name"] = fixture.evidence_root.name
        return fixture.evidence_root

    def verify_tree(self, root):
        return verify_physical_evidence(
            root,
            self.envelope(),
            public_key_hex=self.public,
            expected=self.expected,
            native_execution=self.execution,
            native_artifact=self.artifact,
        )

    def test_actual_assembled_direct_tree_needs_final_receipt_and_stays_unchanged(self):
        root = self.physical_fixture()
        before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        self.assertEqual(self.verify_tree(root), self.payload)
        self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()})
        self.assertFalse(json.loads((root / "manifest.json").read_text())["release_eligible"])

    def test_changed_extra_and_symlinked_direct_evidence_deny(self):
        for change in ("changed", "extra", "symlink"):
            with self.subTest(change=change):
                root = self.physical_fixture()
                manifest = root / "manifest.json"
                if change == "changed":
                    manifest.write_bytes(manifest.read_bytes() + b"\n")
                elif change == "extra":
                    (root / "unrecorded.json").write_text("{}")
                else:
                    (root / "linked").symlink_to(root, target_is_directory=True)
                with self.assertRaises(FinalQualityError):
                    self.verify_tree(root)

    def test_exact_provider_zip_binds_local_bytes_even_after_rechecksumming(self):
        root = self.physical_fixture()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.write(path, str(path.relative_to(root)))
        raw = stream.getvalue()
        artifact = {**self.artifact, "size_in_bytes": len(raw), "digest_sha256": hashlib.sha256(raw).hexdigest()}
        compare_provider_zip(stream, root, artifact)
        manifest = root / "manifest.json"
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        checksums = root / "checksums/SHA256SUMS"
        rows = checksums.read_text().splitlines()
        checksums.write_text(
            "\n".join(
                hashlib.sha256(manifest.read_bytes()).hexdigest() + "  manifest.json"
                if row.endswith("  manifest.json")
                else row
                for row in rows
            )
            + "\n"
        )
        self.assertEqual(quality_evidence._validate_checksums(root.resolve(), checksums.resolve()), [])
        with self.assertRaisesRegex(FinalQualityError, "native ZIP local"):
            compare_provider_zip(stream, root, artifact)

    def test_provider_zip_digest_and_unsafe_member_are_rejected(self):
        root = self.physical_fixture()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../escape", "unexpected")
        raw = stream.getvalue()
        artifact = {**self.artifact, "size_in_bytes": len(raw), "digest_sha256": hashlib.sha256(raw).hexdigest()}
        with self.assertRaisesRegex(FinalQualityError, "member path"):
            compare_provider_zip(stream, root, artifact)
        with self.assertRaisesRegex(FinalQualityError, "ZIP bytes"):
            compare_provider_zip(stream, root, {**artifact, "digest_sha256": "0" * 64})

    def test_native_records_are_independent_and_reject_borrowed_provider_objects(self):
        check_url = "https://api.github.com/repos/" + self.expected["repository"] + "/check-runs/4567"
        native = {
            "/actions/jobs/3456": {
                "id": 3456,
                "run_id": 1234,
                "run_attempt": 1,
                "head_sha": "a" * 40,
                "runner_id": 78,
                "status": "completed",
                "conclusion": "success",
                "check_run_url": check_url,
                "completed_at": "1970-01-01T00:16:40Z",
            },
            "/check-runs/4567": {"id": 4567, "head_sha": "a" * 40, "status": "completed", "conclusion": "success"},
            "/actions/artifacts/7890": {
                "id": 7890,
                "name": self.artifact["name"],
                "expired": False,
                "workflow_run": {"id": 1234, "head_sha": "a" * 40},
                "digest": "sha256:" + "c" * 64,
                "size_in_bytes": 4096,
            },
        }
        with patch.object(final_quality, "_native_read", side_effect=lambda path: native[path]):
            self.assertEqual(
                final_quality.native_records(self.payload, run_id=1234, source_sha="a" * 40),
                (self.execution, self.artifact),
            )
        for path, key, value in (
            ("/actions/jobs/3456", "run_id", 9999),
            ("/actions/jobs/3456", "runner_id", 79),
            ("/actions/jobs/3456", "conclusion", "failure"),
            ("/check-runs/4567", "head_sha", "b" * 40),
            ("/actions/artifacts/7890", "expired", True),
            ("/actions/artifacts/7890", "workflow_run", {"id": 9999, "head_sha": "a" * 40}),
        ):
            changed = copy.deepcopy(native)
            changed[path][key] = value
            with (
                self.subTest(path=path, key=key),
                patch.object(final_quality, "_native_read", side_effect=lambda path, changed=changed: changed[path]),
            ):
                with self.assertRaises(FinalQualityError):
                    final_quality.native_records(self.payload, run_id=1234, source_sha="a" * 40)

    def test_actual_import_entry_copies_only_after_all_proofs_and_preserves_raw_export(self):
        root = self.physical_fixture()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.write(path, str(path.relative_to(root)))
        raw = stream.getvalue()
        self.artifact.update(size_in_bytes=len(raw), digest_sha256=hashlib.sha256(raw).hexdigest())
        receipts = root.parent.parent / "receipts"
        receipt_directory = receipts / "root-final-quality-fixture"
        receipt_directory.mkdir(parents=True)
        receipt_file = receipt_directory / "final-quality-receipt.json"
        receipt_file.write_text(json.dumps(self.envelope()))
        destination = root.parent.parent / "verified"
        with (
            patch.object(final_quality, "ROOT_PUBLIC_KEY_HEX", self.public),
            patch.object(final_quality, "native_records", return_value=(self.execution, self.artifact)),
            patch.object(
                final_quality,
                "verify_provider_zip",
                side_effect=lambda tree, artifact: compare_provider_zip(stream, tree, artifact),
            ),
        ):
            self.assertEqual(
                final_quality.import_physical_inputs(
                    root.parent,
                    receipts,
                    destination,
                    run_id=1234,
                    source_sha="a" * 40,
                    controller_sha="b" * 40,
                ),
                1,
            )
        self.assertEqual(
            (destination / root.name / "manifest.json").read_bytes(), (root / "manifest.json").read_bytes()
        )
        self.assertFalse(json.loads((destination / root.name / "manifest.json").read_text())["release_eligible"])
        # A later invocation cannot silently adopt an existing aggregate tree.
        with self.assertRaisesRegex(FinalQualityError, "destination already exists"):
            final_quality.import_physical_inputs(
                root.parent, receipts, destination, run_id=1234, source_sha="a" * 40, controller_sha="b" * 40
            )
