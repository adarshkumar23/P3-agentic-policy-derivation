"""Shared helpers for opa-eval-backed unit tests (test-only local Rego evaluation).

Never point these helpers at a live OPA deployment — see the scope note in
`tests/unit/test_derivation_engine.py` and the repo-level instructions in
CLAUDE.md / the task briefing for Workstream L.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


def opa_eval(rego_text: str, input_data: dict, query: str) -> dict:
    """Evaluate `query` against a single Rego module using the local `opa` CLI.

    Mirrors `tests/unit/test_derivation_engine.py`'s `_opa_eval` helper.
    Raises via assertion if `opa eval` itself fails (nonzero exit). Does NOT
    raise if the query result is undefined -- callers that need to
    distinguish "no result" should use `opa_eval_raw` instead.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f:
        f.write(rego_text)
        rego_path = f.name
    try:
        proc = subprocess.run(
            [
                "opa",
                "eval",
                "--format",
                "json",
                "--input",
                "/dev/stdin",
                "--data",
                rego_path,
                query,
            ],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0, f"opa eval failed: {proc.stderr}"
        result = json.loads(proc.stdout)
        expressions = result["result"][0]["expressions"]
        return expressions[0]["value"]
    finally:
        Path(rego_path).unlink(missing_ok=True)


def opa_eval_bundle_dir(bundle_dir: str, input_data: dict, query: str) -> dict:
    """Evaluate `query` against every `.rego` file in `bundle_dir`.

    Simulates a real multi-tenant OPA deployment where every tenant's
    compiled policy is bundled together under `--data <dir>`, so this
    proves runtime isolation between packages compiled into the *same*
    bundle, not just isolation between two single-file evaluations.

    Returns a dict with keys:
      - "ok": bool -- True if `opa eval` exited 0 and produced a result.
      - "value": the decoded expression value if "ok" is True, else None.
      - "raw_stdout" / "raw_stderr": for debugging assertion failures.
    """
    proc = subprocess.run(
        [
            "opa",
            "eval",
            "--format",
            "json",
            "--input",
            "/dev/stdin",
            "--data",
            bundle_dir,
            query,
        ],
        input=json.dumps(input_data),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        return {"ok": False, "value": None, "raw_stdout": proc.stdout, "raw_stderr": proc.stderr}
    result = json.loads(proc.stdout)
    # opa eval returns {} (no "result" key) when the query path is undefined
    # -- e.g. querying a package that was never compiled into the bundle.
    if "result" not in result or not result["result"]:
        return {"ok": True, "value": None, "raw_stdout": proc.stdout, "raw_stderr": proc.stderr}
    expressions = result["result"][0]["expressions"]
    return {"ok": True, "value": expressions[0]["value"], "raw_stdout": proc.stdout, "raw_stderr": proc.stderr}
