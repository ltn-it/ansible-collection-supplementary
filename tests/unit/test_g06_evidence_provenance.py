"""Pending/candidate barriers survive copying and independently verified reaggregation.

Real Ed25519 signatures and provider ZIP/member bytes are exercised. Native
GitHub HTTP observations are explicitly modeled; these are not operating proof.
"""

import contextlib
import copy
import hashlib
import importlib
import io
import json
import os
import runpy
import subprocess
import sys
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import g06_final_quality as g
from scripts import quality_evidence as q
from tests.unit import test_g06_final_quality as final_fixtures
from tests.unit import test_quality_evidence as evidence_fixtures

_REAL_NATIVE_RECORDS = g.native_records
_REAL_PROVIDER_ZIP = g.verify_provider_zip


class PendingProvenanceTests(unittest.TestCase):
    def generic(self, candidate=False, release_inputs=False):
        fixture = evidence_fixtures.QualityEvidenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        registry = fixture._registry()
        fixture._junit()
        if release_inputs:
            fixture._release_security("a" * 40)
            fixture._release_dependencies(source_commit="a" * 40)
        if candidate:
            value = json.loads(registry.read_text())
            value["roles"]["demo_role"]["candidate_targets"] = ["ubuntu-24.04"]
            registry.write_text(json.dumps(value))
        environment = {
            **fixture._environment(),
            "QUALITY_EVIDENCE_PREREQUISITES_JSON": json.dumps(fixture._prerequisites()),
        }
        return fixture, registry, environment

    def physical(self):
        fixture = final_fixtures.FinalQualityTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        root = fixture.physical_fixture()
        repo = root.parent.parent
        env = {
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "1234",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "ltn-it/ansible-collection-supplementary",
        }
        return fixture, root, repo, env

    def test_unverified_physical_preliminary_cannot_promote(self):
        _fixture, preliminary, repo, env = self.physical()
        output = preliminary.parent / "unverified-aggregate"
        before = (preliminary / "manifest.json").read_bytes()
        with patch.dict(os.environ, env, clear=False), self.assertRaises(q.EvidenceError):
            q.assemble(
                output, input_roots=[preliminary], registry_path=repo / "meta/role-coverage.yml", repository_root=repo
            )
        self.assertFalse(output.exists())
        self.assertEqual((preliminary / "manifest.json").read_bytes(), before)

    def test_existing_pending_output_cannot_be_reassembled_as_release(self):
        f, registry, env = self.generic(release_inputs=True)
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(
                q.assemble(
                    f.evidence_root,
                    input_roots=[f.artifacts],
                    registry_path=registry,
                    repository_root=f.repository,
                    preliminary=True,
                ),
                0,
            )
            before = (f.evidence_root / "manifest.json").read_bytes()
            with self.assertRaises(q.EvidenceError):
                q.assemble(
                    f.evidence_root,
                    input_roots=[f.artifacts],
                    registry_path=registry,
                    repository_root=f.repository,
                    release_mode=True,
                )
        self.assertEqual((f.evidence_root / "manifest.json").read_bytes(), before)

    def test_candidate_reaggregation_cannot_drop_mode(self):
        f, registry, env = self.generic(candidate=True)
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(
                q.assemble(
                    f.evidence_root,
                    input_roots=[f.artifacts],
                    registry_path=registry,
                    repository_root=f.repository,
                    candidate_mode=True,
                ),
                0,
            )
            with self.assertRaises(q.EvidenceError):
                q.assemble(
                    f.artifacts / "candidate-reaggregate",
                    input_roots=[f.evidence_root],
                    registry_path=registry,
                    repository_root=f.repository,
                )

    def test_legitimate_signed_final_import_and_raw_bytes_remain_positive(self):
        f, root, repo, env = self.physical()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.write(path, str(path.relative_to(root)))
        raw = stream.getvalue()
        f.artifact.update(size_in_bytes=len(raw), digest_sha256=hashlib.sha256(raw).hexdigest())
        envelope = f.envelope()
        self.assertEqual(f.verify_tree(root), f.payload)
        g.compare_provider_zip(io.BytesIO(raw), root, f.artifact)
        receipts = root.parent / "receipts"
        (receipts / "signed").mkdir(parents=True)
        (receipts / "signed/final-quality-receipt.json").write_text(json.dumps(envelope))
        downloaded = root.parent / "downloaded"
        downloaded.mkdir()
        import shutil

        shutil.copytree(root, downloaded / root.name)
        output = root.parent / "actually-verified-import"
        before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        with (
            patch.object(g, "ROOT_PUBLIC_KEY_HEX", f.public),
            patch.object(g, "native_records", return_value=(f.execution, f.artifact)),
            patch.object(
                g,
                "verify_provider_zip",
                side_effect=lambda tree, artifact: g.compare_provider_zip(io.BytesIO(raw), tree, artifact),
            ),
        ):
            self.assertEqual(
                g.import_physical_inputs(
                    downloaded, receipts, output, run_id=1234, source_sha="a" * 40, controller_sha="b" * 40
                ),
                1,
            )
        self.assertEqual(
            before,
            {
                str(p.relative_to(output / root.name)): p.read_bytes()
                for p in (output / root.name).rglob("*")
                if p.is_file()
            },
        )
        self.assertFalse(json.loads((output / root.name / "manifest.json").read_text())["release_eligible"])
        print(
            "POSITIVE real Ed25519 + ZIP bytes preserve original tree; native provider facts modeled",
            flush=True,
        )

    def test_nested_legacy_pending_cannot_promote(self):
        _fixture, preliminary, repo, env = self.physical()
        import shutil

        expanded = preliminary.parent / "legacy-transport" / "expanded" / "archive-1" / "cell"
        shutil.copytree(preliminary, expanded)
        with patch.dict(os.environ, env, clear=False), self.assertRaises(q.EvidenceError):
            q.assemble(
                preliminary.parent / "legacy-reaggregate",
                input_roots=[expanded.parent.parent.parent],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
            )

    def test_mixed_pending_and_raw_reports_cannot_promote(self):
        _fixture, preliminary, repo, env = self.physical()
        with patch.dict(os.environ, env, clear=False), self.assertRaises(q.EvidenceError):
            q.assemble(
                preliminary.parent / "mixed-reaggregate",
                input_roots=[preliminary, preliminary.parent / "junit"],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
            )

    def test_ordinary_business_final_release_positive_unchanged(self):
        f, registry, env = self.generic(release_inputs=True)
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(
                q.assemble(
                    f.evidence_root,
                    input_roots=[f.artifacts],
                    registry_path=registry,
                    repository_root=f.repository,
                    release_mode=True,
                ),
                0,
            )
            self.assertEqual(q.validate(f.evidence_root, repository_root=f.repository, release_mode=True), 0)
        self.assertTrue(json.loads((f.evidence_root / "manifest.json").read_text())["release_eligible"])
        print("POSITIVE ordinary business final release remains eligible without newRootdomain invention", flush=True)

    def release_dependencies_for_cell(self, cell, coverage, profile, scenario):
        """Adapt existing real release fixtures to the two closed physical cells."""
        import shutil

        dependencies = cell.artifacts / "dependencies"
        for path in sorted(dependencies.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if path.is_file():
                path.write_text(path.read_text().replace("demo-tiny", scenario))
            if "demo-tiny" in path.name:
                path.rename(path.with_name(path.name.replace("demo-tiny", scenario)))
        config = cell.repository / "molecule" / scenario / "molecule.yml"
        config.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cell.repository / "molecule/demo-tiny/molecule.yml", config)
        registry_evidence = dependencies / ("role-coverage-" + scenario + "-ubuntu-24.04.yml")
        registry_evidence.write_text(json.dumps(coverage))
        path = dependencies / "test-application-dependencies.json"
        payload = json.loads(path.read_bytes())
        payload["profile"] = profile.replace("_", "-")
        payload["registry_policy"]["sha256"] = hashlib.sha256(registry_evidence.read_bytes()).hexdigest()
        payload["applications"][0]["evidence_sha256"] = hashlib.sha256(
            (dependencies / payload["applications"][0]["source_inventory"]).read_bytes()
        ).hexdigest()
        path.write_text(json.dumps(payload))
        if profile == "application_acceptance":
            bound = {
                "schema_version": 1,
                "profile": "application-acceptance",
                "scenario": scenario,
                "target": "ubuntu-24.04",
                "source_commit": "a" * 40,
            }
            (dependencies / "python-packages-keycloak-acceptance-target.json").write_text(
                json.dumps(
                    {**bound, "source": "target-venv", "packages": [{"name": "playwright", "version": "1.55.0"}]}
                )
            )
            (dependencies / "browser-runtime-keycloak-acceptance-target.json").write_text(
                json.dumps(
                    {
                        **bound,
                        "source": "playwright-target-runtime",
                        "playwright_version": "1.55.0",
                        "chromium": {
                            "name": "chromium",
                            "channel": "chrome",
                            "version": "140.0.7339.16",
                            "executable": "/opt/google/chrome/chrome",
                            "sha256": "b" * 64,
                        },
                        "operating_system": {"id": "ubuntu", "version_id": "24.04", "distro": "ubuntu-24.04"},
                        "os_packages": [
                            {
                                "name": "libc6",
                                "version": "2.39-0ubuntu8.4",
                                "architecture": "amd64",
                                "source_name": "glibc",
                                "source_version": "2.39-0ubuntu8.4",
                            }
                        ],
                    }
                )
            )

    def signed_import(self, *, representative=False, release=False):
        """Both genuine Main cell identities, real signatures and ZIP bytes.

        Only native HTTP is modeled. Root key never exists outside this EE test.
        """
        import shutil

        fixtures, blobs, records = [], {}, {}
        environment = {
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "1234",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": g.SOURCE_REPOSITORY,
            "G06_VALIDATION_CONTROLLER_SHA": "b" * 40,
        }
        self.enterContext(patch.dict(os.environ, environment, clear=False))
        common = None
        for index, (profile, scenario, _target) in enumerate(sorted(g.MAIN_PHYSICAL_CELLS)):
            f = final_fixtures.FinalQualityTests()
            f.setUp()
            self.addCleanup(f.doCleanups)
            if common is None:
                common = f
            else:
                f.key, f.public, f.header = common.key, common.public, common.header
                f.payload["signer_public_key_hex"] = common.public
            cell = evidence_fixtures.QualityEvidenceTests()
            cell.setUp()
            self.addCleanup(cell.doCleanups)
            if release:
                cell._release_security("a" * 40)
                cell._release_dependencies(source_commit="a" * 40)
            registry = cell._registry()
            coverage = json.loads(registry.read_bytes())
            role = coverage["roles"]["demo_role"]
            role.update(tiny="not-applicable", heavy="not-applicable", application_acceptance="not-applicable")
            role.update(heavy="supported", application_acceptance="supported")
            definition = coverage["scenarios"].pop("demo-tiny")
            for item_profile, item_scenario, _cell_target in sorted(g.MAIN_PHYSICAL_CELLS):
                coverage["scenarios"][item_scenario] = {**definition, "profile": item_profile.replace("_", "-")}
            registry.write_text(json.dumps(coverage))
            if release:
                self.release_dependencies_for_cell(cell, coverage, profile, scenario)
            if representative:
                logs = cell.artifacts / "logs"
                logs.mkdir()
                # Public deterministic bytes: 16 MiB/cell plus 1,000 real files.
                # No host input, credentials, VM effects or claimed native timing.
                block = b"".join(
                    hashlib.sha256((profile + ":" + str(i)).encode()).hexdigest().encode() + b"\n" for i in range(4096)
                )
                with (logs / "representative-public-capture.log").open("wb") as stream:
                    remaining = 16 * 1024**2
                    while remaining:
                        chunk = block[:remaining]
                        stream.write(chunk)
                        remaining -= len(chunk)
                for i in range(1000):
                    (logs / ("public-" + str(i) + ".txt")).write_text(
                        "public bounded fixture " + profile + str(i) + "\n"
                    )
            junit = cell._junit()
            junit.write_text(
                junit.read_text()
                .replace("demo-tiny", scenario)
                .replace('name="profile" value="tiny"', 'name="profile" value="' + profile + '"')
                .replace('name="run_attempt" value="2"', 'name="run_attempt" value="1"')
            )
            self.assertEqual(
                q.assemble(
                    cell.evidence_root,
                    input_roots=[cell.artifacts],
                    registry_path=registry,
                    repository_root=cell.repository,
                    profiles=[profile],
                    scenarios=[scenario],
                    preliminary=True,
                ),
                0,
            )
            f.expected.update(profile=profile, scenario=scenario)
            f.payload.update(f.expected)
            f.artifact.update(id=7890 + index, name="quality-result-" + profile)
            f.execution.update(job_id=3456 + index, check_run_id=4567 + index)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in sorted(cell.evidence_root.rglob("*")):
                    if path.is_file():
                        archive.write(path, str(path.relative_to(cell.evidence_root)))
            raw = stream.getvalue()
            f.artifact.update(size_in_bytes=len(raw), digest_sha256=hashlib.sha256(raw).hexdigest())
            fixtures.append((f, cell, coverage))
            blobs[f.artifact["id"]] = raw
            records[f.artifact["id"]] = (f.execution, f.artifact)
        first, cell, coverage = fixtures[0]
        repo = cell.repository
        merged = copy.deepcopy(coverage)
        merged["roles"]["demo_role"].update(heavy="supported", application_acceptance="supported")
        merged["scenarios"].update(fixtures[1][2]["scenarios"])
        (repo / "meta/role-coverage.yml").write_text(json.dumps(merged))
        if release:
            for _f, original, _coverage in fixtures:
                for config in (original.repository / "molecule").glob("*/molecule.yml"):
                    destination_config = repo / config.relative_to(original.repository)
                    destination_config.parent.mkdir(parents=True, exist_ok=True)
                    if destination_config != config:
                        shutil.copy2(config, destination_config)
            self.release_security_source = cell.evidence_root / "security"
        downloaded, receipts = cell.artifacts / "downloaded", cell.artifacts / "receipts"
        downloaded.mkdir()
        for f, original, _coverage in fixtures:
            shutil.copytree(original.evidence_root, downloaded / f.artifact["name"])
            directory = receipts / str(f.artifact["id"])
            directory.mkdir(parents=True)
            (directory / "final-quality-receipt.json").write_text(json.dumps(f.envelope()))
        self.http_blobs, self.http_records = blobs, records
        destination = cell.artifacts / "verified-import"
        native = self.enterContext(
            patch.object(g, "native_records", side_effect=lambda payload, **_kw: records[payload["artifact"]["id"]])
        )
        provider = self.enterContext(
            patch.object(
                g,
                "verify_provider_zip",
                side_effect=lambda tree, artifact: g.compare_provider_zip(
                    io.BytesIO(blobs[artifact["id"]]), tree, artifact
                ),
            )
        )
        self.enterContext(patch.object(g, "ROOT_PUBLIC_KEY_HEX", common.public))
        proof = g.verified_physical_inputs(
            downloaded, receipts, destination, run_id=1234, source_sha="a" * 40, controller_sha="b" * 40
        )
        # Return the original corresponding to the first retained artifact for byte comparisons.
        return first, fixtures[0][1].evidence_root, repo, destination, proof, native, provider

    def test_verified_import_assemble_validate_then_fresh_reaggregation(self):
        f, raw, repo, inputs, proof, native, provider = self.signed_import()
        output = inputs.parent / "aggregate"
        before = {str(p.relative_to(raw)): p.read_bytes() for p in raw.rglob("*") if p.is_file()}
        self.assertEqual(
            q.assemble(
                output,
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=proof,
            ),
            0,
        )
        self.assertEqual(q.validate(output, repository_root=repo, final_inputs=proof), 0)
        self.assertEqual(native.call_count, 2)
        self.assertEqual(provider.call_count, 2)
        manifest = json.loads((output / "manifest.json").read_bytes())
        retained = output / manifest["root_final_quality_inputs"][0]["cell"]
        self.assertEqual(
            before, {str(p.relative_to(retained)): p.read_bytes() for p in retained.rglob("*") if p.is_file()}
        )
        # Fresh process boundary modeled by discarding opaque capability. It must
        # read native facts and ZIP bytes again, not trust persisted metadata.
        self.assertEqual(q.validate(output, repository_root=repo), 0)
        self.assertEqual(native.call_count, 4)
        self.assertEqual(provider.call_count, 4)
        second = inputs.parent / "reaggregated"
        self.assertEqual(
            q.assemble(
                second, input_roots=[output], registry_path=repo / "meta/role-coverage.yml", repository_root=repo
            ),
            0,
        )
        self.assertEqual(q.validate(second, repository_root=repo), 0)
        self.assertEqual(native.call_count, 8)
        self.assertEqual(provider.call_count, 8)

    def test_missing_expected_controller_and_offline_native_hold(self):
        _f, _raw, repo, inputs, proof, native, _provider = self.signed_import()
        output = inputs.parent / "aggregate"
        self.assertEqual(
            q.assemble(
                output,
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=proof,
            ),
            0,
        )
        with patch.dict(os.environ, {"G06_VALIDATION_CONTROLLER_SHA": ""}):
            self.assertEqual(q.validate(output, repository_root=repo), 1)
        native.side_effect = g.FinalQualityError("native token unavailable")
        self.assertEqual(q.validate(output, repository_root=repo), 1)
        with self.assertRaises(q.EvidenceError):
            q.assemble(
                inputs.parent / "offline-reaggregate",
                input_roots=[output],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
            )

    def test_opaque_forgery_and_postverification_tree_tamper_deny(self):
        _f, _raw, repo, inputs, proof, _native, _provider = self.signed_import()
        with self.assertRaises(q.EvidenceError):
            q.assemble(
                inputs.parent / "forged",
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=g.VerifiedPhysicalInputs(),
            )
        report = next(inputs.rglob("*.xml"))
        report.write_bytes(report.read_bytes() + b"\n")
        with self.assertRaises(q.EvidenceError):
            q.assemble(
                inputs.parent / "tampered",
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=proof,
            )

    def test_verified_public_signature_only_is_scanner_exception(self):
        _f, _raw, repo, inputs, proof, _native, _provider = self.signed_import()
        output = inputs.parent / "aggregate"
        self.assertEqual(
            q.assemble(
                output,
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=proof,
            ),
            0,
        )
        self.assertFalse(q.scan_evidence(output)["clean"])  # No blanket JWT/JSON exemption.
        self.assertTrue(q.scan_evidence(output, final_inputs=proof)["clean"])
        envelope = next((output / "root-final-inputs").rglob("final-quality-receipt.json"))
        envelope.write_bytes(envelope.read_bytes() + b" ")
        with self.assertRaises(g.FinalQualityError):
            q.scan_evidence(output, final_inputs=proof)

    def test_mapping_removal_and_changed_aggregate_reports_deny(self):
        _f, _raw, repo, inputs, proof, _native, _provider = self.signed_import()
        output = inputs.parent / "aggregate"
        self.assertEqual(
            q.assemble(
                output,
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=proof,
            ),
            0,
        )
        manifest_path = output / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        changed = copy.deepcopy(manifest)
        del changed["root_final_quality_inputs"]
        manifest_path.write_text(json.dumps(changed))
        self.assertEqual(q.validate(output, repository_root=repo), 1)
        manifest_path.write_text(json.dumps(manifest))
        report = output / manifest["results"][0]["junit"][0]
        report.write_bytes(report.read_bytes() + b"\n")
        self.assertEqual(q.validate(output, repository_root=repo), 1)

    def test_main_coverage_is_exact_cells_not_only_count(self):
        _f, _raw, _repo, _inputs, proof, _native, _provider = self.signed_import()
        g.require_main_coverage(proof)
        entries = g._entries(proof)
        partial = g._mint([(entries[0]["root"], entries[0]["envelope"], entries[0]["inventory"])])
        with self.assertRaisesRegex(g.FinalQualityError, "exact Main physical cell coverage"):
            g.require_main_coverage(partial)

    def test_retained_proof_copies_obey_existing_total_cap(self):
        _f, _raw, repo, inputs, proof, _native, _provider = self.signed_import()
        with patch.object(q, "MAX_EVIDENCE_TOTAL_BYTES", 1), self.assertRaises((q.EvidenceError, g.FinalQualityError)):
            q.assemble(
                inputs.parent / "overbound",
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=proof,
            )

    def native_http_transport(self, native, provider):
        native.side_effect = _REAL_NATIVE_RECORDS
        provider.side_effect = _REAL_PROVIDER_ZIP
        requests = []
        rows = {}
        for artifact_id, (execution, artifact) in self.http_records.items():
            rows["/actions/jobs/" + str(execution["job_id"])] = {
                "id": execution["job_id"],
                "run_id": 1234,
                "run_attempt": 1,
                "head_sha": "a" * 40,
                "status": "completed",
                "conclusion": "success",
                "runner_id": 78,
                "completed_at": "1970-01-01T00:16:40Z",
                "check_run_url": "https://api.github.com/repos/"
                + g.SOURCE_REPOSITORY
                + "/check-runs/"
                + str(execution["check_run_id"]),
            }
            rows["/check-runs/" + str(execution["check_run_id"])] = {
                "id": execution["check_run_id"],
                "head_sha": "a" * 40,
                "status": "completed",
                "conclusion": "success",
            }
            rows["/actions/artifacts/" + str(artifact_id)] = {
                "id": artifact_id,
                "name": artifact["name"],
                "size_in_bytes": artifact["size_in_bytes"],
                "expired": False,
                "workflow_run": {"id": 1234, "head_sha": "a" * 40},
                "digest": "sha256:" + artifact["digest_sha256"],
            }

        class Response(io.BytesIO):
            status = 200

        def opened(request, timeout):
            self.assertEqual(timeout, 30)
            if isinstance(request, str):
                self.assertTrue(request.startswith("https://results-receiver.actions.githubusercontent.com/"))
                artifact_id = int(request.rsplit("/", 1)[1])
                requests.append("signed-blob-without-auth")
                return Response(self.http_blobs[artifact_id])
            prefix = "https://api.github.com/repos/" + g.SOURCE_REPOSITORY
            self.assertTrue(request.full_url.startswith(prefix))
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-read-only-fixture")
            requests.append("native-metadata")
            return Response(json.dumps(rows[request.full_url[len(prefix) :]]).encode())

        case = self

        class Connection:
            def __init__(self, host, timeout):
                case.assertEqual((host, timeout), ("api.github.com", 30))

            def request(self, method, path, headers):
                case.assertEqual(method, "GET")
                case.assertEqual(headers["Authorization"], "Bearer synthetic-read-only-fixture")
                self.artifact_id = int(path.split("/")[-2])
                requests.append("native-zip-redirect")

            def getresponse(self):
                return SimpleNamespace(
                    status=302,
                    getheader=lambda _name, _default: (
                        "https://results-receiver.actions.githubusercontent.com/" + str(self.artifact_id)
                    ),
                )

            def close(self):
                pass

        self.enterContext(patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-read-only-fixture"}))
        self.enterContext(patch.object(g.http.client, "HTTPSConnection", Connection))
        self.enterContext(patch.object(g.urllib.request, "build_opener", return_value=SimpleNamespace(open=opened)))
        return requests

    def test_actual_native_read_zip_transport_and_whole_phase_request_budget(self):
        fixture_started = time.monotonic()
        _f, _raw, repo, inputs, proof, native, provider = self.signed_import(representative=True)
        requests = self.native_http_transport(native, provider)
        output = inputs.parent / "http-aggregate"
        start = time.monotonic()
        self.assertEqual(
            q.assemble(
                output,
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=proof,
            ),
            0,
        )
        self.assertEqual(q.validate(output, repository_root=repo, final_inputs=proof), 0)
        self.assertEqual(requests, [])  # Same-process reuse has no second network round.
        self.assertEqual(q.validate(output, repository_root=repo), 0)
        self.assertEqual(requests.count("native-metadata"), 6)
        self.assertEqual(requests.count("native-zip-redirect"), 2)
        self.assertEqual(requests.count("signed-blob-without-auth"), 2)
        print(
            "MODELED_PHASE_BUDGET "
            + json.dumps(
                {
                    "seconds": time.monotonic() - start,
                    "cells": 2,
                    "fresh_http_requests": len(requests),
                    "same_process_duplicate_requests": 0,
                    "network": "modeled; real crypto, tree, ZIP and aggregate validation",
                    "per_request_timeout_seconds": 30,
                    "per_zip_download_ceiling_seconds": 300,
                    "fixed_whole_verification_phase_seconds": g.VERIFICATION_SECONDS,
                    "job_safety_reserve_seconds": 90,
                    "fixture_setup_seconds": start - fixture_started,
                    "representative_capture_bytes_per_cell": 16 * 1024**2,
                    "additional_files_per_cell": 1000,
                    "release_admission_existing_job_seconds": 600,
                    "deadline_changed": False,
                }
            ),
            flush=True,
        )

    def test_expired_whole_phase_denies_before_any_native_read(self):
        calls = []

        @g.bounded_verification
        def operation():
            calls.append("entered")

        with patch.dict(os.environ, {"G06_FINAL_PHASE_DEADLINE": str(time.monotonic() - 1)}):
            with self.assertRaisesRegex(g.FinalQualityError, "phase budget exhausted"):
                operation()
        self.assertEqual(calls, [])

    def test_slow_provider_cannot_reset_original_phase_or_proof_deadline(self):
        clock = [1000.0]
        with (
            patch.object(g.time, "monotonic", side_effect=lambda: clock[0]),
            patch.dict(os.environ, {"G06_FINAL_PHASE_DEADLINE": "1510"}),
        ):

            @g.bounded_verification
            def operation():
                self.assertEqual(g._request_timeout(), 30)
                clock[0] += 230
                self.assertEqual(g._request_timeout(), 10)

                @g.bounded_verification
                def nested():
                    self.assertEqual(g._request_timeout(), 10)
                    clock[0] += 11

                nested()

            with self.assertRaisesRegex(g.FinalQualityError, "phase budget exhausted"):
                operation()
        self.assertIsNone(g._PHASE_DEADLINE.get())

    def test_two_cell_release_fixture_passes_all_ordinary_final_semantics(self):
        import shutil

        _f, _raw, repo, inputs, proof, _native, _provider = self.signed_import(release=True)
        output = inputs.parent / "release-aggregate"
        shutil.copytree(self.release_security_source, output / "security")
        with patch.dict(
            os.environ,
            {
                "QUALITY_EVIDENCE_PREREQUISITES_JSON": json.dumps(
                    evidence_fixtures.QualityEvidenceTests()._prerequisites()
                )
            },
        ):
            self.assertEqual(
                q.assemble(
                    output,
                    input_roots=[inputs],
                    registry_path=repo / "meta/role-coverage.yml",
                    repository_root=repo,
                    release_mode=True,
                    final_inputs=proof,
                ),
                0,
            )
            self.assertEqual(q.validate(output, repository_root=repo, release_mode=True, final_inputs=proof), 0)

    def test_change_between_zip_verification_and_copy_is_never_adopted(self):
        _f, _raw, _repo, inputs, _proof, _native, _provider = self.signed_import()
        entries = g._entries(_proof)
        original = g.shutil.copytree

        def racing(source, destination, *args, **kwargs):
            result = original(source, destination, *args, **kwargs)
            target = Path(destination) / "manifest.json"
            if target.is_file():
                target.write_bytes(target.read_bytes() + b"\n")
            return result

        with (
            patch.object(g.shutil, "copytree", side_effect=racing),
            self.assertRaisesRegex(g.FinalQualityError, "changed before proof binding"),
        ):
            g.persist_inputs(_proof, inputs.parent / "raced-copy")
        self.assertEqual(len(entries), 2)

    def run_real_cli(self, form, arguments, public, *, pin_is_wrong=False):
        """Unchanged Source __main__, independent test Root pin, real CLI parsing.

        The test deployment public key is substituted at main entry after its
        literal assignment. Signing and verification remain genuine; production
        key bytes/code are never read or modified. No proof or assembler mock.
        """
        module_path = str(Path(g.__file__).resolve())
        expected_pin = public if not pin_is_wrong else "0" * 64
        previous_trace = sys.gettrace()
        package = importlib.import_module("scripts")
        original_alias = sys.modules.get("scripts.g06_final_quality")
        original_direct_alias = sys.modules.get("g06_final_quality")
        original_attribute = getattr(package, "g06_final_quality", None)

        def deployment_pin(frame, event, _argument):
            if event == "call" and frame.f_code.co_filename == module_path and frame.f_code.co_name == "main":
                self.assertEqual(
                    frame.f_globals["ROOT_PUBLIC_KEY_HEX"],
                    "15a46de8e59602953884a1fe7138f40cfb3c12245af1f8e93a6f615421fe5788",
                )
                frame.f_globals["ROOT_PUBLIC_KEY_HEX"] = expected_pin
            return deployment_pin

        try:
            with patch.object(sys, "argv", [module_path, *arguments]):
                sys.settrace(deployment_pin)
                with self.assertRaises(SystemExit) as terminal:
                    if form == "path":
                        with patch.object(sys, "path", [str(Path(module_path).parent), *sys.path]):
                            runpy.run_path(module_path, run_name="__main__")
                    else:
                        runpy.run_module("scripts.g06_final_quality", run_name="__main__", alter_sys=True)
            return terminal.exception.code
        finally:
            sys.settrace(previous_trace)
            sys.modules["scripts.g06_final_quality"] = original_alias
            package.g06_final_quality = original_attribute
            if original_direct_alias is None:
                sys.modules.pop("g06_final_quality", None)
            else:
                sys.modules["g06_final_quality"] = original_direct_alias

    def test_real_path_and_module_cli_keep_one_registry_then_fresh_package_validation(self):
        import shutil

        f, _raw, repo, inputs, _proof, native, provider = self.signed_import(release=True)
        requests = self.native_http_transport(native, provider)
        environment = {
            "QUALITY_EVIDENCE_PREREQUISITES_JSON": json.dumps(evidence_fixtures.QualityEvidenceTests()._prerequisites())
        }
        with contextlib.chdir(repo), patch.dict(os.environ, environment):
            for form in ("path", "module"):
                output = inputs.parent / ("cli-" + form)
                shutil.copytree(self.release_security_source, output / "security")
                arguments = [
                    "--downloaded",
                    str(inputs.parent / "downloaded"),
                    "--receipts",
                    str(inputs.parent / "receipts"),
                    "--destination",
                    str(inputs.parent / ("cli-import-" + form)),
                    "--run-id",
                    "1234",
                    "--source-sha",
                    "a" * 40,
                    "--controller-sha",
                    "b" * 40,
                    "--aggregate-root",
                    str(output),
                    "--registry",
                    str(repo / "meta/role-coverage.yml"),
                    "--run-attempt",
                    "1",
                ]
                self.assertEqual(self.run_real_cli(form, arguments, f.public), 0)
                self.assertEqual(len(requests), 10 if form == "path" else 30)
                # In-process package integration only. Clean direct-script
                # startup is independently covered by the fresh-child test.
                self.assertEqual(q.validate(output, repository_root=repo, release_mode=True), 0)
                self.assertEqual(len(requests), 20 if form == "path" else 40)

    def test_real_cli_wrong_independent_deployment_key_denies(self):
        f, _raw, repo, inputs, _proof, native, provider = self.signed_import(release=True)
        self.native_http_transport(native, provider)
        destination = inputs.parent / "wrong-key-import"
        arguments = [
            "--downloaded",
            str(inputs.parent / "downloaded"),
            "--receipts",
            str(inputs.parent / "receipts"),
            "--destination",
            str(destination),
            "--run-id",
            "1234",
            "--source-sha",
            "a" * 40,
            "--controller-sha",
            "b" * 40,
        ]
        self.assertEqual(self.run_real_cli("path", arguments, f.public, pin_is_wrong=True), 1)
        self.assertFalse(destination.exists())

    def test_copied_preliminary_collector_needs_no_final_companion_or_crypto(self):
        import shutil

        f, registry, environment = self.generic()
        collector = f.base / "copied-context" / "quality_evidence.py"
        collector.parent.mkdir()
        shutil.copy2(q.__file__, collector)
        self.assertEqual([path.name for path in collector.parent.iterdir()], ["quality_evidence.py"])
        # Actual isolated script invocation: no scripts package or final verifier
        # is present in this copied context, matching preliminary producer needs.
        env = {**os.environ, **environment, "GITHUB_TOKEN": "", "PYTHONPATH": ""}
        args = [
            sys.executable,
            "-I",
            "-B",
            str(collector),
            "assemble",
            "--root",
            str(f.evidence_root),
            "--input-root",
            str(f.artifacts),
            "--registry",
            str(registry),
            "--repository-root",
            str(f.repository),
            "--profile",
            "tiny",
            "--scenario",
            "demo-tiny",
            "--target",
            "ubuntu-24.04",
            "--run-attempt",
            "2",
            "--expected-commit",
            "a" * 40,
            "--preliminary",
        ]
        # Fixed EE interpreter + exact repository collector; only test-owned paths.
        result = subprocess.run(  # noqa: S603
            args, cwd=f.repository, env=env, capture_output=True, timeout=30, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads((f.evidence_root / "manifest.json").read_bytes())["root_finalization"], "pending")

    def test_aggregate_native_tuple_cannot_be_relabelled(self):
        _f, _raw, repo, inputs, proof, _native, _provider = self.signed_import()
        output = inputs.parent / "tuple-aggregate"
        self.assertEqual(
            q.assemble(
                output,
                input_roots=[inputs],
                registry_path=repo / "meta/role-coverage.yml",
                repository_root=repo,
                final_inputs=proof,
            ),
            0,
        )
        path = output / "manifest.json"
        original = json.loads(path.read_bytes())
        for field, value in (
            ("workflow_run_id", "9999"),
            ("workflow_attempt", "2"),
            ("repository", "foreign/repository"),
        ):
            with self.subTest(field=field):
                changed = {**original, field: value}
                path.write_text(json.dumps(changed))
                self.assertEqual(q.validate(output, repository_root=repo), 1)

    def test_clean_direct_physical_consumers_without_source_package_on_path(self):
        """Fresh child interpreter: no inherited scripts module/PYTHONPATH.

        Only HTTP and independent public test-deployment key are substituted.
        The actual direct-script import path and all verification code execute.
        """
        import shutil

        f, _raw, repo, inputs, proof, _native, _provider = self.signed_import(release=True)
        output = inputs.parent / "clean-native-input"
        shutil.copytree(self.release_security_source, output / "security")
        prerequisites = json.dumps(evidence_fixtures.QualityEvidenceTests()._prerequisites())
        with patch.dict(os.environ, {"QUALITY_EVIDENCE_PREREQUISITES_JSON": prerequisites}):
            self.assertEqual(
                q.assemble(
                    output,
                    input_roots=[inputs],
                    registry_path=repo / "meta/role-coverage.yml",
                    repository_root=repo,
                    release_mode=True,
                    final_inputs=proof,
                ),
                0,
            )
        fixture = inputs.parent / "clean-http-fixture"
        fixture.mkdir()
        rows = {}
        for artifact_id, (execution, artifact) in self.http_records.items():
            rows["/actions/jobs/" + str(execution["job_id"])] = {
                "id": execution["job_id"],
                "run_id": 1234,
                "run_attempt": 1,
                "head_sha": "a" * 40,
                "status": "completed",
                "conclusion": "success",
                "runner_id": 78,
                "completed_at": "1970-01-01T00:16:40Z",
                "check_run_url": "https://api.github.com/repos/"
                + g.SOURCE_REPOSITORY
                + "/check-runs/"
                + str(execution["check_run_id"]),
            }
            rows["/check-runs/" + str(execution["check_run_id"])] = {
                "id": execution["check_run_id"],
                "head_sha": "a" * 40,
                "status": "completed",
                "conclusion": "success",
            }
            rows["/actions/artifacts/" + str(artifact_id)] = {
                "id": artifact_id,
                "name": artifact["name"],
                "size_in_bytes": artifact["size_in_bytes"],
                "expired": False,
                "workflow_run": {"id": 1234, "head_sha": "a" * 40},
                "digest": "sha256:" + artifact["digest_sha256"],
            }
            (fixture / (str(artifact_id) + ".zip")).write_bytes(self.http_blobs[artifact_id])
        (fixture / "metadata.json").write_text(json.dumps({"rows": rows, "public": f.public}))
        adapter = r"""import atexit,io,json,os,runpy,sys,urllib.request,http.client,importlib.util
from pathlib import Path
from types import SimpleNamespace
fixture=Path(sys.argv[1]); script=Path(sys.argv[2]).resolve(); argv=sys.argv[2:]
# Match a direct script's native path, retaining installed stdlib/dependencies only.
source=str(script.parent.parent)
sys.path=[str(script.parent)]+[p for p in sys.path if p and p not in {source,str(script.parent)}]
for name in list(sys.modules):
    if name=='scripts' or name.startswith('scripts.') or name in {'quality_evidence','g06_final_quality'}:
        del sys.modules[name]
assert 'PYTHONPATH' not in os.environ
assert importlib.util.find_spec('scripts') is None
print('CLEAN_DIRECT_CONTEXT scripts_package_absent=true',flush=True)
data=json.loads((fixture/'metadata.json').read_bytes()); calls=[]
class Response(io.BytesIO):
    status=200
    def getheader(self,name,default):
        return 'https://results-receiver.actions.githubusercontent.com/'+str(self.artifact_id)
def opened(request,timeout):
    assert 0<timeout<=30
    if isinstance(request,str):
        assert request.startswith('https://results-receiver.actions.githubusercontent.com/')
        calls.append('blob')
        return Response((fixture/(request.rsplit('/',1)[1]+'.zip')).read_bytes())
    prefix='https://api.github.com/repos/ltn-it/ansible-collection-supplementary'
    assert request.full_url.startswith(prefix)
    assert request.get_header('Authorization')=='Bearer synthetic-read-only-fixture'
    calls.append('metadata')
    return Response(json.dumps(data['rows'][request.full_url[len(prefix):]]).encode())
class Connection:
    def __init__(self,host,timeout):
        assert host=='api.github.com' and 0<timeout<=30
    def request(self,method,path,headers):
        assert method=='GET' and headers['Authorization']=='Bearer synthetic-read-only-fixture'
        self.artifact_id=int(path.split('/')[-2]); calls.append('redirect')
    def getresponse(self):
        response=Response();response.status=302;response.artifact_id=self.artifact_id
        return response
    def close(self): pass
urllib.request.build_opener=lambda *unused:SimpleNamespace(open=opened)
http.client.HTTPSConnection=Connection
def deployment(frame,event,unused):
    if (event=='call' and frame.f_code.co_name=='_verify_persisted_inputs'
        and Path(frame.f_code.co_filename).name=='g06_final_quality.py'):
        expected=('15a46de8e59602953884a1fe7138f40c'
                  'fb3c12245af1f8e93a6f615421fe5788')
        assert frame.f_globals['ROOT_PUBLIC_KEY_HEX']==expected
        frame.f_globals['ROOT_PUBLIC_KEY_HEX']=data['public']
    return deployment
sys.settrace(deployment)
atexit.register(lambda:print('CLEAN_HTTP_REQUESTS '+str(len(calls)),flush=True))
sys.argv=argv
runpy.run_path(str(script),run_name='__main__')
"""
        env = {
            **os.environ,
            "GITHUB_TOKEN": "synthetic-read-only-fixture",
            "QUALITY_EVIDENCE_PREREQUISITES_JSON": prerequisites,
        }
        env.pop("PYTHONPATH", None)
        for name in ("quality_evidence.py", "keycloak-evidence.py"):
            with self.subTest(entry=name):
                args = [
                    sys.executable,
                    "-c",
                    adapter,
                    str(fixture),
                    str(Path(q.__file__).with_name(name)),
                    "validate",
                    "--root",
                    str(output),
                    "--expected-commit",
                    "a" * 40,
                    "--release",
                ]
                # Fixed interpreter, reviewed collector, public fixture-only HTTP adapter.
                result = subprocess.run(args, cwd=repo, env=env, capture_output=True, timeout=30, check=False)  # noqa: S603
                self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
                self.assertIn("scripts_package_absent=true", result.stdout.decode())
                self.assertIn("CLEAN_HTTP_REQUESTS 10", result.stdout.decode())

        # The same actual direct entry can reaggregate persisted proof, and its
        # output must again independently validate in another fresh interpreter.
        reassembled = inputs.parent / "clean-direct-reaggregate"
        shutil.copytree(self.release_security_source, reassembled / "security")
        script = str(Path(q.__file__).resolve())
        for command in (
            [
                "assemble",
                "--root",
                str(reassembled),
                "--input-root",
                str(output),
                "--registry",
                str(repo / "meta/role-coverage.yml"),
                "--repository-root",
                str(repo),
                "--release",
                "--expected-commit",
                "a" * 40,
            ],
            ["validate", "--root", str(reassembled), "--release", "--expected-commit", "a" * 40],
        ):
            args = [sys.executable, "-c", adapter, str(fixture), script, *command]
            # Fixed collector and fixture-only adapter, never caller commands.
            result = subprocess.run(args, cwd=repo, env=env, capture_output=True, timeout=30, check=False)  # noqa: S603
            self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
            self.assertIn("CLEAN_HTTP_REQUESTS 10", result.stdout.decode())
        data = json.loads((fixture / "metadata.json").read_bytes())
        data["public"] = "0" * 64
        (fixture / "metadata.json").write_text(json.dumps(data))
        args = [
            sys.executable,
            "-c",
            adapter,
            str(fixture),
            script,
            "validate",
            "--root",
            str(output),
            "--release",
            "--expected-commit",
            "a" * 40,
        ]
        # Independent wrong deployment key must hold with real signature code.
        result = subprocess.run(args, cwd=repo, env=env, capture_output=True, timeout=30, check=False)  # noqa: S603
        self.assertEqual(result.returncode, 1)
        self.assertIn("physical final proof unavailable or invalid", result.stderr.decode())
        print(
            "CLEAN_DIRECT_CLOSURE quality/keycloak validate + direct assemble/revalidate0; wrong-key1; "
            "fresh interpreter, no PYTHONPATH/scripts package; each positive10 HTTP reads",
            flush=True,
        )
