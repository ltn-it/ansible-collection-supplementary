"""Extract the actual event writer functions for the frozen CAS regression suite."""

import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def shell_function(path, name):
    text = path.read_text()
    match = re.search(r"(?m)^( +)" + re.escape(name) + r"\(\) \{\n", text)
    if match is None:
        raise AssertionError(f"missing shell function {name}")
    end = text.index("\n" + match[1] + "}", match.end())
    return textwrap.dedent(text[match.start() : end + len(match[1]) + 2])


class RetainedReviewContracts:
    @staticmethod
    def _rerun_shell_function(name):
        return shell_function(ROOT / ".github/workflows/current-revision-rerun.yml", name)
