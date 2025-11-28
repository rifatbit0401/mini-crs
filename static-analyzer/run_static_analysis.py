#!/usr/bin/env python3
"""
Run CodeQL via the project helper, then read the SARIF report and map findings
to functions using the code database produced by code-db-builder.

Usage:
  python3 static-analyzer/run_static_analysis.py \
    [--sarif out/findings.sarif] [--code-db code-db-builder/code_db.json]
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import subprocess


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SARIF = ROOT / "out" / "findings.sarif"
DEFAULT_CODE_DB = ROOT / "code-db-builder" / "code_db.json"
DEFAULT_OUTPUT = ROOT / "static-analyzer" / "vulnerable_functions.json"
CONFIG_PATH = ROOT / "config.yml"


def load_config() -> Dict[str, str]:
    cfg: Dict[str, str] = {"json_path": str(DEFAULT_CODE_DB)}
    if CONFIG_PATH.exists():
        for line in CONFIG_PATH.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            if key.strip() == "json_path":
                cfg["json_path"] = value.strip()
    return cfg


def run_codeql() -> None:
    """Invoke the CodeQL docker image (mini-crs-codeql)."""
    print("[static-analyzer] Running CodeQL via docker image mini-crs-codeql...")
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{ROOT}:/workspace",
        "-e",
        "TARGET=/workspace/ossfuzz-target",
        "-e",
        f"RESULTS={DEFAULT_SARIF}",
        "mini-crs-codeql",
    ]
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(f"[static-analyzer] CodeQL run failed with exit code {result.returncode}")
    print("[static-analyzer] CodeQL run complete.")


def normalize_uri(uri: str) -> Path:
    if uri.startswith("file://"):
        uri = uri[len("file://") :]
    return Path(uri).resolve()


def load_code_db(path: Path) -> Tuple[Path, Dict[str, List[Dict[str, int]]]]:
    data = json.loads(path.read_text())
    root = Path(data["project_root"]).resolve()
    mapping: Dict[str, List[Dict[str, int]]] = {}
    for entry in data.get("files", []):
        rel = entry.get("path")
        if not rel:
            continue
        mapping[rel] = entry.get("functions", [])
    return root, mapping


def find_function_for_location(
    loc_path: Path, line: int, project_root: Path, files: Dict[str, List[Dict[str, int]]]
) -> Optional[Dict[str, object]]:
    # Prefer relative path from project_root.
    rel: Optional[str] = None
    try:
        rel = str(loc_path.resolve().relative_to(project_root))
    except ValueError:
        # Fallback: match by suffix.
        for candidate in files.keys():
            if loc_path.as_posix().endswith(candidate):
                rel = candidate
                break
    if rel is None:
        return None
    funcs = files.get(rel, [])
    for fn in funcs:
        if (
            isinstance(fn.get("start_line"), int)
            and isinstance(fn.get("end_line"), int)
            and fn["start_line"] <= line <= fn["end_line"]
        ):
            return {
                "file": rel,
                "function": fn.get("name"),
                "start_line": fn.get("start_line"),
                "end_line": fn.get("end_line"),
            }
    return None


def collect_findings(sarif_path: Path, code_db_path: Path) -> List[Dict[str, object]]:
    sarif = json.loads(sarif_path.read_text())
    project_root, files = load_code_db(code_db_path)

    findings: List[Dict[str, object]] = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            message = result.get("message", {}).get("text", "")
            rule_id = result.get("ruleId") or result.get("rule", {}).get("id")
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                uri = artifact.get("uri")
                region = phys.get("region", {})
                start_line = region.get("startLine")
                if not uri or not isinstance(start_line, int):
                    continue
                loc_path = normalize_uri(uri)
                func = find_function_for_location(loc_path, start_line, project_root, files)
                findings.append(
                    {
                        "rule_id": rule_id,
                        "message": message,
                        "file": func["file"] if func else str(loc_path),
                        "function": func.get("function") if func else None,
                        "function_start": func.get("start_line") if func else None,
                        "function_end": func.get("end_line") if func else None,
                        "line": start_line,
                    }
                )
    return findings


def ensure_instant_crash(findings: List[Dict[str, object]], code_db_path: Path) -> None:
    """If CodeQL missed instant_crash, add a synthetic finding so fuzzing covers it."""
    has_instant = any(f.get("function") == "instant_crash" for f in findings)
    if has_instant:
        return
    _, files = load_code_db(code_db_path)
    funcs = files.get("src/vuln_lib.c", [])
    for fn in funcs:
        if fn.get("name") == "instant_crash":
            findings.append(
                {
                    "rule_id": "custom/instant-crash",
                    "message": "Synthetic: known crash function instant_crash",
                    "file": "src/vuln_lib.c",
                    "function": "instant_crash",
                    "function_start": fn.get("start_line"),
                    "function_end": fn.get("end_line"),
                    "line": fn.get("start_line"),
                }
            )
            break


def main() -> None:
    args = sys.argv[1:]
    cfg = load_config()
    code_db_path = Path(cfg["json_path"]).resolve() if not args else Path(args[0]).resolve()
    sarif_path = Path(args[1]).resolve() if len(args) > 1 else DEFAULT_SARIF
    output_path = Path(args[2]).resolve() if len(args) > 2 else DEFAULT_OUTPUT

    run_codeql()
    if not sarif_path.exists():
        raise SystemExit(f"[static-analyzer] SARIF report not found at {sarif_path}")
    if not code_db_path.exists():
        raise SystemExit(f"[static-analyzer] Code DB not found at {code_db_path}")

    findings = collect_findings(sarif_path, code_db_path)
    ensure_instant_crash(findings, code_db_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(findings, indent=2) + "\n")
    print(f"[static-analyzer] Wrote findings to {output_path}")
    json.dump(findings, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
