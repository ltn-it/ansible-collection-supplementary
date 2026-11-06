"""Actual review-content classifiers only; no transport or provider effects."""

import ast
import json
import re
import shutil
import subprocess
import unittest

from unit.review_event_contract_helpers import ROOT

NEGATIVES = (
    "I can't review this pull request.",
    "I can\u2019t review this pull request.",
    "I can't review any files.",
    "I can\u2019t review any files.",
    "I wasn't able to review any files.",
    "I wasn\u2019t able to review any files.",
    "I isn't able to review any files.",
    "I isn\u2019t able to review any files.",
)
POSITIVE = "I can review any files."
WORKFLOWS = (".github/workflows/copilot-review.yml",)


class CannotReviewClassifierTests(unittest.TestCase):
    def canonical(self):
        names = {"FAILURE_MARKERS", "ReviewContentError", "normalize", "require_usable_review_content"}
        parsed = ast.parse((ROOT / "scripts/review_content_markers.py").read_text())
        selected = [
            node
            for node in parsed.body
            if getattr(node, "name", None) in names
            or isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in names
        ]
        namespace = {}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "actual-pure-classifier", "exec"), namespace)  # noqa: S102 -- selected literal/constants and pure function definitions only.
        return namespace

    def run_jq(self, program, payload, args=()):
        result = subprocess.run(  # noqa: S603 -- actual readonly classifier and local JSON fixture.
            [shutil.which("jq") or "jq", *args, program],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.strip()

    def test_python_and_every_actual_jq_contraction_chain_agree(self):
        canonical = self.canonical()
        self.assertIn("cannotreviewthispullrequest", canonical["FAILURE_MARKERS"])
        self.assertIn("cannotreviewanyfiles", canonical["FAILURE_MARKERS"])
        chains = []
        for name in WORKFLOWS:
            text = (ROOT / name).read_text()
            chains.extend(re.findall(r'gsub\("can\[.*?\]t"; "cannot"\) \| gsub\("n\[.*?\]t"; " not"\)', text))
            self.assertEqual(text.count('gsub("n['), text.count('gsub("can['), name)
        self.assertEqual(1, len(chains))
        for phrase in (*NEGATIVES, POSITIVE):
            normalized = canonical["normalize"](phrase)
            for chain in chains:
                self.assertEqual(
                    normalized,
                    json.loads(self.run_jq("ascii_downcase | " + chain + r' | gsub("\\s"; "")', phrase)),
                )
            for inline in (False, True):
                if phrase == POSITIVE:
                    canonical["require_usable_review_content"](phrase, [])
                else:
                    with self.assertRaises(canonical["ReviewContentError"]):
                        canonical["require_usable_review_content"](
                            "Reviewed." if inline else phrase, [phrase] if inline else []
                        )

    def test_actual_publisher_content_counts_reject_body_and_inline_negatives(self):
        text = (ROOT / WORKFLOWS[0]).read_text()
        program = re.search(r"'(def normalize_review_text:.*?\| @tsv)'", text, re.S)[1]
        args = ["-r"]
        for key, value in (
            ("unable_marker", "Unable to review this pull request"),
            ("no_files_marker", "No files were reviewed"),
            ("quota_exhausted_marker", "Quota exhausted"),
            ("quota_exceeded_marker", "Quota exceeded"),
            ("suppressed_comments_marker", "Suppressed comments"),
        ):
            args.extend(("--arg", key, value))
        for phrase in (*NEGATIVES, POSITIVE):
            for inline in (False, True):
                node = {
                    "body": "Reviewed." if inline else phrase,
                    "comments": {"nodes": [{"body": phrase}] if inline else []},
                }
                counts = self.run_jq(program, {"data": {"node": node}}, args).split()
                self.assertEqual("0" if phrase == POSITIVE else "1", counts[0])
