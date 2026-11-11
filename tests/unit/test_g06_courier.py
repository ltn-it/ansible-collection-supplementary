"""Bounded Main courier transport; network/provider APIs are explicit fixtures."""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yaml
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
COURIER = ROOT / "scripts/g06_courier"


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, COURIER / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


codec = load_module("lit_g06_courier_codec", "codec.py")
with patch.dict(sys.modules, {"codec": codec}):
    native_job = load_module("lit_g06_courier_native", "native_job.py")
pull_image = load_module("lit_g06_courier_pull", "pull_image.py")


class CourierCodec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.pem = cls.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cls.binding = {
            "transition_before": codec.TRANSITION_BEFORE,
            "operation": "a" * 32,
            "key_sha256": codec.public_digest(cls.key.public_key()),
            "repository": "ltn-it/ansible-collection-supplementary",
            "repository_id": 1103407173,
            "main_sha": "b" * 40,
            "workflow_id": 214182490,
            "run_id": 123,
            "run_attempt": 1,
            "courier_job_id": 456,
            "actor_id": 76040632,
            "actor": "litroc",
            "candidate_artifact_id": 789,
            "candidate_digest": "d" * 64,
            "candidate_size": 1024,
            "controller_sha": "e" * 40,
            "issued_at": 1000,
            "cutoff_at": 1900,
        }

    def test_roundtrip_never_places_plaintext_token_in_transport(self):
        token = "SYNTHETIC-BEARER-DO-NOT-USE"  # noqa: S105 -- Inert test bearer.
        sealed = codec.seal(token, self.binding, self.pem, 1000)
        self.assertNotIn(token.encode(), sealed)
        self.assertEqual(codec.open_handoff(sealed, self.key, self.binding, 1001), token)

    def test_wrong_run_key_actor_deadline_or_ciphertext_denies(self):
        sealed = codec.seal("SYNTHETIC-BEARER-DO-NOT-USE", self.binding, self.pem, 1000)
        for field, value in [
            ("run_id", 124),
            ("main_sha", "f" * 40),
            ("actor", "litdeg"),
            ("operation", "f" * 32),
            ("cutoff_at", 1901),
        ]:
            expected = {**self.binding, field: value}
            with self.assertRaises(ValueError):
                codec.open_handoff(sealed, self.key, expected, 1001)
        with self.assertRaisesRegex(ValueError, "courier-expired-or-future"):
            codec.open_handoff(sealed, self.key, self.binding, 1901)
        bad = json.loads(sealed)
        raw = bytearray(base64.b64decode(bad["ciphertext"]))
        raw[-1] ^= 1
        bad["ciphertext"] = base64.b64encode(raw).decode()
        with self.assertRaises(InvalidTag):
            codec.open_handoff(codec.canonical(bad), self.key, self.binding, 1001)

    def test_actual_fresh_source_public_binding_is_valid_and_encryptable(self):
        public = ROOT / ".lit/g06-courier.json"
        cfg = native_job.config(public)
        self.assertEqual(cfg["operation"], "96e125e4dfcb450ea9e771f7232b9907")
        binding = {
            **self.binding,
            "operation": cfg["operation"],
            "key_sha256": cfg["public_key_sha256"],
            "controller_sha": cfg["controller_commit_sha"],
        }
        sealed = codec.seal("SYNTHETIC-BEARER-DO-NOT-USE", binding, cfg["public_key_pem"].encode(), 1000)
        self.assertEqual(json.loads(sealed)["binding"], binding)

    def test_duplicate_json_fields_deny(self):
        with self.assertRaisesRegex(ValueError, "duplicate-field"):
            codec.decode(b'{"schema":1,"schema":2}')


class NativeGuards(unittest.TestCase):
    def test_rerun_stops_before_api_or_ciphertext(self):
        environment = {
            "GITHUB_TOKEN": "SYNTHETIC-BEARER-DO-NOT-USE",
            "GITHUB_RUN_ID": "1",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REPOSITORY": native_job.REPO,
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ATTEMPT": "2",
            "G06_EVENT_BEFORE": native_job.TRANSITION_BEFORE,
            "GITHUB_JOB": "g06-root-courier",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(native_job, "config", return_value={}),
            patch.object(native_job, "api") as api,
            patch.object(native_job, "seal") as seal,
        ):
            with self.assertRaisesRegex(ValueError, "courier-hosted-context"):
                native_job.prepare()
        api.assert_not_called()
        seal.assert_not_called()

    def test_api_does_not_follow_foreign_download_or_print_location(self):
        response = Mock(status=302)
        response.read.return_value = b""
        response.getheader.return_value = "https://foreign.invalid/private?signature=SYNTHETIC"
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(native_job.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(ValueError, "courier-download-origin") as error:
                native_job.api(
                    "/repos/" + native_job.REPO + "/actions/artifacts/1/zip", "SYNTHETIC-BEARER-DO-NOT-USE", 302
                )
        self.assertNotIn("SYNTHETIC", str(error.exception))
        connection.close.assert_called_once()

    def test_public_config_rejects_other_window_before_crypto(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"
            path.write_text(
                '{"schema":1,"operation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
                '"public_key_pem":"synthetic","public_key_sha256":"a",'
                '"controller_commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","hold_seconds":901}'
            )
            with self.assertRaisesRegex(ValueError, "courier-public-config"):
                native_job.config(path)


class PullDeadline(unittest.TestCase):
    def test_only_known_quay_eof_retries_before_envelope(self):
        eof = SimpleNamespace(returncode=1, stdout=b"Get https://quay.io/v2/: unexpected EOF")
        ok = SimpleNamespace(returncode=0, stdout=b"pinned image")
        with (
            patch.dict(os.environ, {"PATH": "/usr/bin", "RUNNER_TEMP": "/fixture/runner-temp"}, clear=True),
            patch.object(pull_image.subprocess, "run", side_effect=[eof, ok]) as run,
            patch.object(pull_image.time, "sleep"),
        ):
            pull_image.prepare()
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(call.args[0], ["docker", "pull", "--platform=linux/amd64", pull_image.IMAGE])
            self.assertLessEqual(call.kwargs["timeout"], 600)
            self.assertNotIn("GITHUB_TOKEN", call.kwargs["env"])

    def test_authentication_or_unknown_failure_never_retries(self):
        with (
            patch.dict(os.environ, {"PATH": "/usr/bin", "RUNNER_TEMP": "/fixture/runner-temp"}, clear=True),
            patch.object(
                pull_image.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b"quay.io unauthorized")
            ) as run,
        ):
            with self.assertRaisesRegex(ValueError, "courier-ee-pull-unknown-or-exhausted"):
                pull_image.prepare()
        run.assert_called_once()


class WorkflowEntry(unittest.TestCase):
    def test_real_prepare_entry_with_workflow_environment_and_actual_public_binding(self):
        source = ROOT / ".lit/g06-courier.json"
        public = native_job.config(source)
        main = "a" * 40
        actor = {"id": 76040632, "login": "litroc", "type": "User"}
        run = {
            "id": 123,
            "run_attempt": 1,
            "workflow_id": 214182490,
            "path": ".github/workflows/collection-ci.yml",
            "event": "push",
            "head_sha": main,
            "head_branch": "main",
            "status": "in_progress",
            "conclusion": None,
            "repository": {"id": 1103407173},
            "actor": actor,
            "triggering_actor": actor,
        }
        candidate = {
            "id": 789,
            "name": "collection-candidate-" + main,
            "expired": False,
            "digest": "sha256:" + "d" * 64,
            "size_in_bytes": 1024,
            "workflow_run": {"id": 123, "head_sha": main},
        }
        responses = [
            {"id": 1103407173, "full_name": native_job.REPO, "private": False},
            {"id": 1269461997, "full_name": native_job.V, "private": False},
            {"protected": True, "commit": {"sha": main}},
            run,
            run,
            {"sha": public["controller_commit_sha"], "tree": {"sha": "e" * 40}},
            {},
            None,
            {"total_count": 1, "artifacts": [candidate]},
            candidate,
            None,
            {
                "total_count": 1,
                "jobs": [
                    {
                        "id": 456,
                        "name": native_job.JOB_NAME,
                        "run_id": 123,
                        "head_sha": main,
                        "status": "in_progress",
                        "conclusion": None,
                    }
                ],
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                "GITHUB_TOKEN": "SYNTHETIC-BEARER-DO-NOT-USE",
                "GITHUB_RUN_ID": "123",
                "GITHUB_SHA": main,
                "GITHUB_REPOSITORY": native_job.REPO,
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_JOB": "g06-root-courier",
                "G06_EVENT_BEFORE": codec.TRANSITION_BEFORE,
                "RUNNER_TEMP": directory,
            }
            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(native_job, "config", return_value=public),
                patch.object(native_job, "api", side_effect=responses),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                native_job.prepare()
            path = Path(directory) / "g06-root-courier/handoff.json"
            raw = path.read_bytes()
            self.assertNotIn(environment["GITHUB_TOKEN"].encode(), raw)
            self.assertEqual(codec.decode(raw)["binding"]["transition_before"], codec.TRANSITION_BEFORE)
            environment["G06_EVENT_BEFORE"] = "f" * 40
            with (
                patch.dict(os.environ, environment, clear=True),
                patch.object(native_job, "config", return_value=public),
                patch.object(native_job, "api") as api,
            ):
                with self.assertRaisesRegex(ValueError, "courier-hosted-context"):
                    native_job.prepare()
            api.assert_not_called()

    def test_fragment_uses_same_transition_before_gate_and_pinned_ee_for_both_entries(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/collection-ci.yml").read_text())
        job = workflow["jobs"]["g06-root-courier"]
        self.assertIn("github.event.before == '" + codec.TRANSITION_BEFORE + "'", job["if"])
        self.assertEqual(job["timeout-minutes"], 30)
        self.assertEqual(job["environment"], "ansible-collection-release-prepare")
        self.assertEqual(job["permissions"], {"actions": "read", "contents": "read"})
        encrypt = next(step for step in job["steps"] if step.get("id") == "encrypt")
        hold = job["steps"][-1]
        self.assertEqual(encrypt["env"]["G06_EVENT_BEFORE"], "${{ github.event.before }}")
        for step in (encrypt, hold):
            command = step["run"]
            for value in (
                pull_image.IMAGE,
                "--read-only",
                "--cap-drop ALL",
                "--security-opt no-new-privileges=true",
                "--pull never",
            ):
                self.assertIn(value, command)
            self.assertNotIn("docker.sock", command)
        self.assertIn("--network none", hold["run"])
        self.assertNotIn("GITHUB_TOKEN", hold["run"])
