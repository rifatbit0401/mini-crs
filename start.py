#!/usr/bin/env python3
"""
Orchestrates a build check and code database generation for the ossfuzz-target project.

Usage:
  python3 start.py [path-to-project] [output-json]

Defaults:
  project path: ./ossfuzz-target
  output json:  ./code-db-builder/code_db.json
"""

import json
import subprocess
import sys
from pathlib import Path

# Allow imports from code-db-builder
ROOT = Path(__file__).resolve().parent
CODE_DB_DIR = ROOT / "code-db-builder"
CONFIG_PATH = ROOT / "config.yml"
sys.path.insert(0, str(CODE_DB_DIR))

import build_code_db  # type: ignore  # noqa: E402


def load_config() -> dict:
    """Load a minimal YAML-style config for the JSON paths."""
    cfg = {
        "json_path": str(CODE_DB_DIR / "code_db.json"),
        "vuln_output": str(ROOT / "static-analyzer" / "vulnerable_functions.json"),
    }
    if not CONFIG_PATH.exists():
        return cfg

    for line in CONFIG_PATH.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key == "json_path" and value:
            cfg["json_path"] = value
        if key == "vuln_output" and value:
            cfg["vuln_output"] = value
    return cfg


def run_check_build() -> None:
    script = ROOT / "builder" / "check_build.sh"
    if not script.exists():
        raise SystemExit(f"[build] Missing build check script at {script}")
    print(f"[build] Running {script} ...")
    result = subprocess.run(["bash", str(script)], cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(f"[build] Build check failed with exit code {result.returncode}")
    print("[build] Build check succeeded.")


def generate_code_db(target: Path, out_path: Path) -> None:
    print(f"[code-db] Scanning {target} ...")
    db = build_code_db.build_db(target)
    out_path.write_text(json.dumps(db, indent=2) + "\n")
    print(f"[code-db] Wrote JSON to {out_path}")
    # Also echo JSON to stdout for immediate visibility.
    json.dump(db, sys.stdout, indent=2)
    sys.stdout.write("\n")


def main() -> None:
    args = sys.argv[1:]
    config = load_config()
    default_out = ROOT / config["json_path"]
    default_vuln_out = ROOT / config["vuln_output"]

    target = Path(args[0]) if len(args) >= 1 else ROOT / "ossfuzz-target"
    out_path = Path(args[1]) if len(args) >= 2 else default_out

    if not target.exists():
        raise SystemExit(f"[code-db] Target path does not exist: {target}")

    run_check_build()
    generate_code_db(target, out_path)

    # Run static analyzer via dockerized CodeQL
    print("[static-analyzer] Running static analysis via CodeQL docker...")
    vuln_out = default_vuln_out
    result = subprocess.run(
        [
            "python3",
            "static-analyzer/run_static_analysis.py",
            str(out_path),
            str(ROOT / "out" / "findings.sarif"),
            str(vuln_out),
        ],
        cwd=ROOT,
    )
    if result.returncode != 0:
        raise SystemExit(f"[static-analyzer] Static analysis failed with exit code {result.returncode}")
    print(f"[static-analyzer] Vulnerable functions written to {vuln_out}")


if __name__ == "__main__":
    main()
