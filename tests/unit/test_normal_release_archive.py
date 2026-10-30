"""Bounded archive transport, crypto arguments and strict historical replay."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("normal_release_archive", ROOT / "scripts/normal_release_archive.py")
ARCHIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCHIVE)
REPO = "lightning-it/ansible-collection-supplementary"
SHA, BASE, HEAD, SOURCE = (letter * 40 for letter in "abcd")
EXPECTED = ARCHIVE.binding(REPO, "1103407173", SHA, BASE, HEAD, SOURCE)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.snapshot = self.root / ARCHIVE.SNAPSHOT
        self.bundle = self.root / ARCHIVE.BUNDLE
        self.value = {
            "version": 1,
            "kind": "normal-release-native-observations",
            "binding": EXPECTED,
            "reads": [
                {"kind": "call", "args": [f"repos/{REPO}/git/ref/heads/main"], "value": {"object": {"sha": SHA}}}
            ],
            "result": {"main_merge": SHA},
        }
        self.snapshot.write_bytes(ARCHIVE.canonical(self.value))
        self.bundle.write_text('{"unit":"signature boundary mocked, not native acceptance"}')

    def verify(self):
        return ARCHIVE.verify_files(self.snapshot, self.bundle, REPO, "1103407173", SHA)

    def test_verification_uses_local_bundle_exact_workflow_and_source_before_decode(self):
        with (
            patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
            patch.object(ARCHIVE.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as command,
        ):
            self.assertEqual(self.value, self.verify())
        self.assertEqual(
            [
                "/usr/bin/gh",
                "attestation",
                "verify",
                str(self.snapshot),
                "--bundle",
                str(self.bundle),
                "--repo",
                REPO,
                "--cert-identity",
                f"https://github.com/{REPO}/.github/workflows/collection-publish.yml@refs/heads/main",
                "--source-ref",
                "refs/heads/main",
                "--source-digest",
                SHA,
            ],
            command.call_args.args[0],
        )
        command.assert_called_once()

    def test_bad_signature_wrong_signer_or_wrong_source_never_decodes_or_replays(self):
        for reason in ("tampered payload", "wrong signer", "wrong source SHA", "wrong bundle"):
            with (
                self.subTest(reason=reason),
                patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
                patch.object(ARCHIVE.subprocess, "run", return_value=SimpleNamespace(returncode=1)),
                patch.object(ARCHIVE, "decode") as decode,
                self.assertRaisesRegex(ValueError, "attestation-verification-failed"),
            ):
                self.verify()
            decode.assert_not_called()

    def test_oversized_symlink_or_missing_bundle_never_calls_verifier(self):
        for defect in ("oversized", "symlink", "missing"):
            with self.subTest(defect=defect), patch.object(ARCHIVE.subprocess, "run") as command:
                self.bundle.unlink(missing_ok=True)
                if defect == "oversized":
                    self.bundle.write_bytes(b"x" * 11)
                elif defect == "symlink":
                    self.bundle.symlink_to(self.snapshot)
                with patch.object(ARCHIVE, "MAX_BUNDLE_BYTES", 10), self.assertRaisesRegex(ValueError, "file-bound"):
                    self.verify()
            command.assert_not_called()

    def test_authenticated_json_still_requires_exact_binding_and_canonical_bounded_shape(self):
        for raw in (
            b'{"version":1,"version":1}\n',
            b"{}",
            b"[" * 65 + b"]" * 65,
            ARCHIVE.canonical(self.value | {"binding": EXPECTED | {"release": BASE}}),
        ):
            self.snapshot.write_bytes(raw)
            with (
                self.subTest(raw=raw[:50]),
                patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
                patch.object(ARCHIVE.subprocess, "run", return_value=SimpleNamespace(returncode=0)),
                self.assertRaises(ValueError),
            ):
                self.verify()

    def test_only_historical_main_tip_is_overlaid_and_complete_consumption_is_mandatory(self):
        replay = ARCHIVE.Replay(self.value, EXPECTED, HEAD)
        self.assertEqual({"object": {"sha": HEAD}}, replay.call(f"repos/{REPO}/git/ref/heads/main"))
        replay.finish({"main_merge": SHA})
        self.assertEqual(SHA, self.value["reads"][0]["value"]["object"]["sha"])
        for defect in ("missing", "extra", "arguments", "main", "result", "binding", "write"):
            value = copy.deepcopy(self.value)
            if defect == "missing":
                value["reads"] = []
            elif defect == "extra":
                value["reads"] *= 2
            elif defect == "arguments":
                value["reads"][0]["args"] = ["repos/other/repository"]
            elif defect == "main":
                value["reads"][0]["value"]["object"]["sha"] = BASE
            elif defect == "result":
                value["result"] = {}
            elif defect == "binding":
                value["binding"] = EXPECTED | {"head": BASE}
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                replay = ARCHIVE.Replay(value, EXPECTED, HEAD)
                replay.call(f"repos/{REPO}/git/ref/heads/main", method="POST" if defect == "write" else "GET")
                replay.finish({"main_merge": SHA})

    def test_capture_pauses_nested_artifact_reads_but_binds_verified_return_and_metadata(self):
        api = Mock()
        metadata = {
            "id": 21,
            "name": "control-proof-1",
            "expired": False,
            "size_in_bytes": 100,
            "digest": "sha256:" + "e" * 64,
        }
        api.pages.return_value = [metadata]
        api.call.return_value = {"verified": "native-observation"}
        run = {"id": 20, "run_attempt": 1, "head_sha": HEAD}

        def original(reader, repository, observed, _name, _filename):
            self.assertEqual(
                [metadata], reader.pages(f"repos/{repository}/actions/runs/{observed['id']}/artifacts", "artifacts")
            )
            return {"version": 1, "binding": "native reader already checked the real download"}

        core = SimpleNamespace(artifact_record=original)
        record = ARCHIVE.Record(api, EXPECTED)
        with ARCHIVE.artifact_reader(core, record):
            native = record.call(f"repos/{REPO}/actions/runs/20")
            proof = core.artifact_record(record, REPO, run, "control-proof-1", "control-proof.json")
        self.assertIs(original, core.artifact_record)
        value = ARCHIVE.decode(record.finish({"checked": True}))
        self.assertEqual(["call", "artifact"], [item["kind"] for item in value["reads"]])
        api.pages.assert_called_once()
        self.assertEqual(metadata, value["reads"][1]["value"]["metadata"])
        api.reset_mock()
        api.call.side_effect = AssertionError("original Actions expired")
        api.pages.side_effect = AssertionError("original artifacts expired")
        replay = ARCHIVE.Replay(value, EXPECTED, SHA)
        with ARCHIVE.artifact_reader(core, replay):
            self.assertEqual(native, replay.call(f"repos/{REPO}/actions/runs/20"))
            self.assertEqual(proof, core.artifact_record(replay, REPO, run, "control-proof-1", "control-proof.json"))
        replay.finish({"checked": True})
        api.call.assert_not_called()
        api.pages.assert_not_called()
        for changed in (run | {"id": 22}, run | {"run_attempt": 2}, run | {"head_sha": BASE}):
            replay = ARCHIVE.Replay(value, EXPECTED, SHA)
            replay.call(f"repos/{REPO}/actions/runs/20")
            with self.subTest(run=changed), self.assertRaisesRegex(ValueError, "order-or-binding"):
                replay.artifact(None, None, REPO, changed, "control-proof-1", "control-proof.json")

    def test_preparation_input_protocol_is_exact_attempt_bound_and_replayed_without_download(self):
        run = {"id": 10, "run_attempt": 2, "head_sha": HEAD}
        name, filename = "normal-release-preparation-2", "preparation-inputs.json"
        metadata = {"id": 99, "name": name, "expired": False, "size_in_bytes": 100}
        original_record = {
            "schema": "collection-normal-preparation/v1",
            "head": HEAD,
            "version_selection": {"requested": "1.2.3-rc.1"},
            "publication": {"github_release": True, "galaxy": False},
        }
        api = Mock()
        api.pages.return_value = [metadata]

        def reader(source, repository, observed, artifact, selected_file):
            self.assertEqual(name, artifact)
            self.assertEqual(filename, selected_file)
            source.pages(f"repos/{repository}/actions/runs/{observed['id']}/artifacts", "artifacts")
            return copy.deepcopy(original_record)

        recorder = ARCHIVE.Record(api, EXPECTED)
        self.assertEqual(original_record, recorder.artifact(reader, recorder, REPO, run, name, filename))
        value = ARCHIVE.decode(recorder.finish({"verified": True}))
        replay = ARCHIVE.Replay(value, EXPECTED, SHA)
        with patch.object(api, "pages", side_effect=AssertionError("historical source expired")):
            self.assertEqual(original_record, replay.artifact(None, None, REPO, run, name, filename))
        replay.finish({"verified": True})
        for wrong_run, wrong_name, wrong_file in (
            (run, "normal-release-preparation-1", filename),
            (run, "normal-release-preparation-0", filename),
            (run, "control-proof-2", filename),
            (run, name, "other-inputs.json"),
            (run | {"run_attempt": True}, "normal-release-preparation-True", filename),
            (run | {"run_attempt": 0}, "normal-release-preparation-0", filename),
            (run | {"run_attempt": -1}, "normal-release-preparation--1", filename),
        ):
            original = Mock()
            with self.subTest(run=wrong_run, name=wrong_name, filename=wrong_file), self.assertRaises(ValueError):
                recorder.artifact(original, recorder, REPO, wrong_run, wrong_name, wrong_file)
            original.assert_not_called()

    def test_record_writes_other_repository_or_unbounded_history_are_closed(self):
        api = Mock()
        recorder = ARCHIVE.Record(api, EXPECTED)
        for path, method in ((f"repos/{REPO}/pulls", "POST"), ("repos/other/repo/pulls", "GET")):
            with self.subTest(path=path), self.assertRaises(ValueError):
                recorder.call(path, method=method)
        api.call.assert_not_called()
        with patch.object(ARCHIVE, "MAX_READS", 0), self.assertRaises(ValueError):
            recorder.add("call", [], {})

    def test_pair_transport_uses_exact_native_asset_ids_and_bounded_streams(self):
        assets = [
            {
                "name": name,
                "id": index,
                "state": "uploaded",
                "size": 10,
                "browser_download_url": "https://untrusted.invalid/ignored",
            }
            for index, name in enumerate((ARCHIVE.SNAPSHOT, ARCHIVE.BUNDLE), 1)
        ]
        original = ARCHIVE.subprocess.Popen

        def transport(_command, **kwargs):
            return original([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 10)"], **kwargs)

        with (
            patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
            patch.object(ARCHIVE.subprocess, "Popen", side_effect=transport) as command,
        ):
            ARCHIVE.download_pair({"assets": assets}, REPO, self.root)
        self.assertEqual(2, command.call_count)
        for index, call in enumerate(command.call_args_list, 1):
            self.assertEqual(f"repos/{REPO}/releases/assets/{index}", call.args[0][-1])
        self.assertEqual(b"x" * 10, self.snapshot.read_bytes())
        self.assertEqual(b"x" * 10, self.bundle.read_bytes())
        for script in ("import sys; sys.stdout.buffer.write(b'x' * 11)", "raise SystemExit(1)"):

            def failed_transport(_command, script=script, **kwargs):
                return original([sys.executable, "-c", script], **kwargs)

            with (
                self.subTest(script=script),
                patch.object(ARCHIVE, "MAX_BYTES", 10),
                patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
                patch.object(ARCHIVE.subprocess, "Popen", side_effect=failed_transport) as command,
                self.assertRaises(ValueError),
            ):
                ARCHIVE.download_pair({"assets": assets}, REPO, self.root)
            command.assert_called_once()

    def test_asset_download_rejects_missing_ambiguous_expired_or_oversized_sources_before_transport(self):
        assets = [
            {"name": name, "id": index, "state": "uploaded", "size": 10}
            for index, name in enumerate((ARCHIVE.SNAPSHOT, ARCHIVE.BUNDLE), 1)
        ]
        for bad in (
            [],
            [assets[0]],
            [assets[0], assets[1] | {"id": 1}],
            [assets[0], assets[0]],
            [assets[0] | {"size": ARCHIVE.MAX_BYTES + 1}],
            [assets[0] | {"id": True}],
            [assets[0] | {"state": "new"}],
        ):
            with (
                self.subTest(assets=bad),
                patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
                patch.object(ARCHIVE.subprocess, "Popen") as process,
                self.assertRaises(ValueError),
            ):
                ARCHIVE.download_pair({"assets": bad}, REPO, self.root)
            process.assert_not_called()


class CompletionTests(unittest.TestCase):
    """Real bounded manifest/profile validation; only the crypto provider is offline."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.context = ARCHIVE.completion_context(REPO, "1103407173", SHA, "1.0.1", True)
        for name in ARCHIVE.completion_assets(self.context):
            (self.assets / name).write_bytes((name + "\n").encode())
        self.manifest = ARCHIVE.local_manifest(self.assets, ARCHIVE.completion_assets(self.context))
        self.published = {
            "id": 40,
            "tag_name": "v1.0.1",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-10-18T00:00:00Z",
            "assets": [
                {
                    "id": i + 1,
                    "name": row["name"],
                    "size": row["size"],
                    "state": "uploaded",
                    "digest": "sha256:" + row["sha256"],
                }
                for i, row in enumerate(self.manifest)
            ],
        }
        self.directory = self.root / "completion"
        self.directory.mkdir()
        self.value = ARCHIVE.completion_document(self.published, self.context, self.manifest)
        (self.directory / ARCHIVE.COMPLETION).write_bytes(ARCHIVE.canonical(self.value))
        (self.directory / ARCHIVE.COMPLETION_BUNDLE).write_text("offline crypto fixture")
        self.published["assets"] += [
            {"id": 100 + i, "name": name, "size": (self.directory / name).stat().st_size, "state": "uploaded"}
            for i, name in enumerate((ARCHIVE.COMPLETION, ARCHIVE.COMPLETION_BUNDLE))
        ]

    def verify(self):
        with (
            patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
            patch.object(ARCHIVE.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as command,
        ):
            result = ARCHIVE.verify_completion_files(self.directory, self.published, self.context)
        self.assertIn("--source-digest", command.call_args.args[0])
        self.assertEqual(SHA, command.call_args.args[0][-1])
        return result

    def test_complete_publication_has_no_dispatch_claim_and_exact_mandatory_assets(self):
        self.assertEqual(self.value, self.verify())
        self.assertEqual(39, len(self.manifest))
        self.assertNotIn("back_sync", self.value)
        self.assertNotIn("release_back_sync_dispatched", self.value["gates"])
        for gate in self.value["gates"].values():
            self.assertIsInstance(gate, bool)
            self.assertTrue(gate)

    def test_raw_release_and_asset_reads_are_offline_and_preserve_completion_verification(self):
        raw = self.root / "observations"
        raw.mkdir()
        index = {"version": 1, "repository": REPO, "calls": {}, "logs": {}, "artifacts": {}, "assets": {}}
        path = f"repos/{REPO}/releases/tags/v1.0.1"
        index["calls"][path] = "read-0.json"
        (raw / "read-0.json").write_text(json.dumps(self.published))
        for asset in self.published["assets"]:
            name = f"asset-{asset['id']}.bin"
            source = self.directory if asset["name"] in {ARCHIVE.COMPLETION, ARCHIVE.COMPLETION_BUNDLE} else self.assets
            (raw / name).write_bytes((source / asset["name"]).read_bytes())
            index["assets"][str(asset["id"])] = name
        (raw / "index.json").write_text(json.dumps(index))
        # Only the signature boundary is mocked; no API/downloader fallback is
        # permitted, and the original profile/manifest/byte checks are actual.
        with (
            ARCHIVE.observation_reads(raw, REPO),
            patch.object(ARCHIVE.subprocess, "Popen", side_effect=AssertionError("network fallback")),
            patch.object(ARCHIVE, "verified_document", return_value=self.value),
        ):
            self.assertEqual(self.published, ARCHIVE.read_release(self.context))
            output = self.root / "raw-reuse"
            self.assertTrue(ARCHIVE.completion_prepare(self.assets, output, self.context))
            for name in (ARCHIVE.COMPLETION, ARCHIVE.COMPLETION_BUNDLE):
                self.assertEqual((self.directory / name).read_bytes(), (output / name).read_bytes())
            asset = self.published["assets"][0]
            original = (raw / index["assets"][str(asset["id"])]).read_bytes()
            (raw / index["assets"][str(asset["id"])]).write_bytes(b"x" * len(original))
            with self.assertRaisesRegex(ValueError, "asset-digest"):
                ARCHIVE.download_assets(self.published, REPO, None, ((asset["name"], asset["size"]),))
        self.assertIsNone(ARCHIVE._OBSERVATIONS)  # pylint: disable=protected-access
        for defect in ("missing", "foreign", "unsafe", "extra", "duplicate"):
            changed = copy.deepcopy(index)
            if defect == "missing":
                (raw / "read-0.json").unlink()
            elif defect == "foreign":
                changed["repository"] = "lightning-it/foreign"
            elif defect == "unsafe":
                changed["calls"][path] = "../read-0.json"
            elif defect == "extra":
                (raw / "unbound").write_text("not a native observation")
            else:
                changed["calls"][f"repos/{REPO}/releases/tags/v9.9.9"] = "read-0.json"
            (raw / "index.json").write_text(json.dumps(changed))
            with self.subTest(defect=defect), self.assertRaises(ValueError), ARCHIVE.observation_reads(raw, REPO):
                pass
            (raw / "read-0.json").write_text(json.dumps(self.published))
            (raw / "unbound").unlink(missing_ok=True)

    def test_missing_duplicate_foreign_or_changed_assets_deny_complete_signed_claim(self):
        original = copy.deepcopy(self.published)
        mutations = (
            lambda v: v["assets"].pop(0),
            lambda v: v["assets"].append(copy.deepcopy(v["assets"][0])),
            lambda v: v["assets"][0].update(name="foreign.json"),
            lambda v: v["assets"][0].update(size=0),
            lambda v: v["assets"][0].update(size=True),
            lambda v: v["assets"][0].update(id=True),
            lambda v: v["assets"][0].update(state="new"),
            lambda v: v["assets"][0].update(digest="sha256:" + "0" * 64),
        )
        for mutate in mutations:
            self.published = copy.deepcopy(original)
            mutate(self.published)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.verify()

    def test_false_claims_or_different_binding_never_authorize_completion(self):
        mutations = (
            lambda v: v.update(schema_version=True),
            lambda v: v.update(back_sync={"dispatch_accepted": True}),
            lambda v: v["binding"].update(galaxy_required=False),
            lambda v: v["binding"].update(galaxy_required=1),
            lambda v: v["binding"].update(profile="generic-minor-manual/v1"),
            lambda v: v["binding"].update(repository="lightning-it/foreign"),
            lambda v: v["binding"].update(release=BASE),
            lambda v: v["release"].update(id=True),
            lambda v: v["gates"].update(github_release_install_smoke=False),
            lambda v: v["gates"].update(github_release_install_smoke=1),
            lambda v: v["assets"].pop(),
        )
        for mutate in mutations:
            value = copy.deepcopy(self.value)
            mutate(value)
            (self.directory / ARCHIVE.COMPLETION).write_bytes(ARCHIVE.canonical(value))
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.verify()

    def test_bad_completion_signature_never_interprets_claim_or_reads_assets(self):
        with (
            patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
            patch.object(ARCHIVE.subprocess, "run", return_value=SimpleNamespace(returncode=1)),
            patch.object(ARCHIVE, "verify_manifest") as manifest,
            self.assertRaisesRegex(ValueError, "attestation-verification-failed"),
        ):
            ARCHIVE.verify_completion_files(self.directory, self.published, self.context)
        manifest.assert_not_called()

    def test_creation_reuses_original_pair_but_partial_pair_and_changed_local_bytes_close(self):
        def download(_published, _repo, output, _limits):
            for name in (ARCHIVE.COMPLETION, ARCHIVE.COMPLETION_BUNDLE):
                (output / name).write_bytes((self.directory / name).read_bytes())

        with (
            patch.object(ARCHIVE, "read_release", return_value=self.published),
            patch.object(ARCHIVE, "download_assets", side_effect=download),
            patch.object(ARCHIVE, "verified_document", return_value=self.value),
        ):
            output = self.root / "reuse"
            self.assertTrue(ARCHIVE.completion_prepare(self.assets, output, self.context))
            for name in (ARCHIVE.COMPLETION, ARCHIVE.COMPLETION_BUNDLE):
                self.assertEqual((self.directory / name).read_bytes(), (output / name).read_bytes())
            (self.assets / self.manifest[0]["name"]).write_text("changed existing bytes")
            with self.assertRaises(ValueError):
                ARCHIVE.completion_prepare(self.assets, self.root / "changed", self.context)
            self.published["assets"].pop()
            with self.assertRaisesRegex(ValueError, "partial-pair"):
                ARCHIVE.completion_prepare(self.assets, self.root / "partial", self.context)

    def test_missing_metadata_digest_requires_actual_bounded_asset_bytes(self):
        self.published["assets"][0]["digest"] = None
        with patch.object(ARCHIVE, "download_assets") as download:
            self.verify()
        downloaded, repo, directory, limits = download.call_args.args
        self.assertEqual(REPO, repo)
        self.assertIsNone(directory)
        self.assertEqual(self.manifest[0]["sha256"], downloaded["assets"][0]["expected_sha256"])
        self.assertEqual(((self.manifest[0]["name"], self.manifest[0]["size"]),), limits)

    def test_new_completion_creates_only_unsigned_bytes_after_exact_base_inventory(self):
        self.published["assets"] = self.published["assets"][:-2]
        with patch.object(ARCHIVE, "read_release", return_value=self.published):
            output = self.root / "new"
            self.assertFalse(ARCHIVE.completion_prepare(self.assets, output, self.context))
        self.assertEqual({ARCHIVE.COMPLETION}, {item.name for item in output.iterdir()})
        self.assertEqual(ARCHIVE.canonical(self.value), (output / ARCHIVE.COMPLETION).read_bytes())

    def test_streamed_asset_fallback_hashes_real_bytes_and_rejects_mismatch_without_file_output(self):
        row = self.manifest[0]
        asset = self.published["assets"][0] | {"expected_sha256": row["sha256"]}
        raw = (self.assets / row["name"]).read_bytes()
        original = ARCHIVE.subprocess.Popen
        for content, valid in ((raw, True), (b"x" * len(raw), False), (raw + b"x", False)):

            def transport(_command, content=content, **kwargs):
                return original([sys.executable, "-c", f"import sys; sys.stdout.buffer.write({content!r})"], **kwargs)

            with (
                self.subTest(valid=valid),
                patch.object(ARCHIVE.shutil, "which", return_value="/usr/bin/gh"),
                patch.object(ARCHIVE.subprocess, "Popen", side_effect=transport),
            ):
                if valid:
                    ARCHIVE.download_assets({"assets": [asset]}, REPO, None, ((row["name"], row["size"]),))
                else:
                    with self.assertRaises(ValueError):
                        ARCHIVE.download_assets({"assets": [asset]}, REPO, None, ((row["name"], row["size"]),))

    def test_actual_publisher_assembly_matches_full_normal_mandatory_profile(self):
        # Fixture source inventory follows the existing CI outputs, not the new
        # completion allowlist. Execute the actual publisher assembly shell.
        candidate = "lit-supplementary-1.0.1.tar.gz"
        evidence = f"collection-evidence-{SHA}.tar.gz"
        longterm = f"collection-release-evidence-{SHA}.tar.gz"
        ci_names = {
            evidence,
            "evidence-manifest.json",
            "sbom.cdx.json",
            "provenance.json",
            "role-coverage.yml",
            "matrix-results.json",
            "candidate.github-attestation.json",
            "sbom.github-attestation.json",
            "evidence.github-attestation.json",
            "attestation-records.json",
            candidate + ".sigstore.json",
            "sbom.cdx.json.sigstore.json",
            evidence + ".sigstore.json",
            "vulnerability-report.json",
            "trivy-vulnerability-report.json",
            "secret-scan-summary.json",
            "release-evidence.json",
            "release-evidence.md",
            "SHA256SUMS.sigstore.json",
            "checksums.github-attestation.json",
            "checksums-attestation-record.json",
            "release-security-receipt.json",
            "release-security-receipt.json.sigstore.json",
            "release-security-receipt.github-attestation.json",
            "release-security-receipt-attestation.json",
        }
        product = self.root / "product"

        def write(relative, data=b"offline assembly fixture\n"):
            path = product / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return path

        for name in ci_names:
            write("incoming/evidence/release-assets/" + name)
        ci_directory = product / "incoming/evidence/release-assets"
        write(
            "incoming/evidence/release-assets/SHA256SUMS",
            b"".join(
                f"{hashlib.sha256((ci_directory / name).read_bytes()).hexdigest()}  {name}\n".encode()
                for name in sorted(ci_names - {"SHA256SUMS.sigstore.json"})
            ),
        )
        raw = b"candidate exact bytes\n"
        write("incoming/candidate/" + candidate, raw)
        write("incoming/candidate/candidate-SHA256SUMS", f"{hashlib.sha256(raw).hexdigest()}  {candidate}\n".encode())
        for name in ("vulnerability-report.json", "trivy-vulnerability-report.json", "secret-scan-summary.json"):
            write("incoming/evidence/evidence/security/" + name)
        for name in (candidate, evidence, "sbom.cdx.json", "SHA256SUMS", "release-security-receipt.json"):
            write("dist/attestation-bundles/" + name + ".attestation.jsonl")
        for name in (longterm, longterm + ".sha256"):
            write("incoming/evidence/long-term/" + name)
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-publish.yml").read_text())
        steps = {step.get("name"): step for step in workflow["jobs"]["publish"]["steps"]}
        from tests.unit.test_normal_release_proof import install_ee_dispatcher

        install_ee_dispatcher(product)
        home = self.root / "ee-home"
        home.mkdir()
        environment = {
            **os.environ,
            "BASH_ENV": os.devnull,
            "CANDIDATE_NAME": candidate,
            "GITHUB_WORKSPACE": str(product),
            "HOME": str(home),
        }
        result = subprocess.run(  # noqa: S603 -- actual offline assembly fixture, no native command.
            ["/bin/bash", "-c", steps["Assemble verified release attachments"]["run"]],
            cwd=product,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        # The following existing steps append the original native pair and
        # publisher checksum signature; they are not supplied by the receipt.
        for name in (ARCHIVE.SNAPSHOT, ARCHIVE.BUNDLE, "SHA256SUMS", "SHA256SUMS.sigstore.json"):
            write("dist/release/" + name)
        self.assertEqual(
            ARCHIVE.completion_assets(self.context), {p.name for p in (product / "dist/release").iterdir()}
        )

    def test_normal_completion_order_preserves_legacy_security_writer_and_has_no_dispatch_claim(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-publish.yml").read_text())
        steps = workflow["jobs"]["publish"]["steps"]
        names = [step.get("name") for step in steps]
        ordered = [
            "Verify GitHub Release download, install, and smoke",
            "Verify Galaxy version install and smoke",
            "Prepare completed normal publication evidence",
            "Attest completed normal publication",
            "Publish and verify completed normal publication evidence",
            "Mint exact back-sync dispatch App token",
            "Trigger release back-sync after verified publication",
            "Attach signed post-publication verification receipt",
        ]
        self.assertEqual(sorted(names.index(name) for name in ordered), [names.index(name) for name in ordered])
        by_name = {step.get("name"): step for step in steps}
        for name in ordered[2:5]:
            self.assertIn("env.NORMAL_TWO_STAGE == 'true'", by_name[name]["if"])
        self.assertIn("outputs.reused != 'true'", by_name[ordered[3]]["if"])
        self.assertIn("env.NORMAL_TWO_STAGE != 'true'", by_name[ordered[-1]]["if"])
        upload = by_name[ordered[4]]["run"]
        self.assertEqual(1, upload.count("gh release upload"))
        self.assertNotIn("--clobber", upload)
        self.assertIn("--operation completion-verify", upload)
        finalizer = workflow["jobs"]["publish-security-finalize"]["steps"]
        self.assertFalse(any("completed normal publication" in step.get("name", "") for step in finalizer))


if __name__ == "__main__":
    unittest.main()
