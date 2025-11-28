#!/usr/bin/env python3
"""
Collect AFL++ crash inputs and map them back to harnesses/functions.

Scans fuzzer/out-* directories, reads crash files, and writes a JSON summary:
{
  "harnesses": [
    {
      "harness": "fuzzer/harnesses/instant_crash_afl.c",
      "function": "instant_crash",
      "crashes": [
        {
          "path": "fuzzer/out-instant_test2/default/crashes/id:000000,sig:11,...",
          "sig": "11",
          "time": "267",
          "execs": "29"
        }
      ]
    },
    ...
  ]
}
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
HARNESS_INDEX = ROOT / "fuzzer" / "harnesses.json"
FUZZER_DIR = ROOT / "fuzzer"
CONFIG_PATH = ROOT / "config.yml"
DEFAULT_OUTPUT = ROOT / "fuzzer" / "crashes_report.json"


def load_config(default_out: Path) -> Path:
    """Load crash_report path from config.yml if present."""
    out = default_out
    if CONFIG_PATH.exists():
        for line in CONFIG_PATH.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            if key.strip() == "crash_report":
                raw = value.strip()
                out = Path(raw)
                if not out.is_absolute():
                    out = (ROOT / out).resolve()
                break
    return out


def derive_function_from_harness(path: Path) -> str:
    """Extract function name from harness filename or first comment line."""
    name = path.stem  # e.g., instant_crash_afl
    if name.endswith("_afl"):
        name = name[: -len("_afl")]
    try:
        first = path.read_text().splitlines()[0]
        if "for " in first:
            name = first.split("for", 1)[1].strip().strip(" */")
    except (FileNotFoundError, UnicodeDecodeError, IndexError):
        pass
    return name


def parse_crash_filename(fname: str) -> Dict[str, str]:
    """Parse AFL crash filename (id:000000,sig:11,...)."""
    meta: Dict[str, str] = {}
    parts = fname.split(",")
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            meta[k] = v
    return meta


def collect_crashes_for_harness(base_name: str) -> List[Dict[str, str]]:
    """
    Find crash files under fuzzer/out-<base_name>*.
    Returns list of {path, sig?, time?, execs?}.
    """
    crashes: List[Dict[str, str]] = []
    patterns = [
        FUZZER_DIR.glob(f"out-{base_name}*/default/crashes/*"),
        FUZZER_DIR.glob(f"out-{base_name}/default/crashes/*"),
    ]
    for pattern in patterns:
        try:
            for path in pattern:
                if path.name == "README.txt":
                    continue
                if not path.is_file():
                    continue
                rel = path.relative_to(ROOT)
                meta = parse_crash_filename(path.name)
                entry = {"path": rel.as_posix()}
                entry.update(meta)
                crashes.append(entry)
        except PermissionError:
            # Skip directories not readable (e.g., root-owned old runs).
            continue
    return crashes


def load_harnesses() -> List[Path]:
    if not HARNESS_INDEX.exists():
        raise SystemExit(f"[collect] Harness index not found: {HARNESS_INDEX}")
    data = json.loads(HARNESS_INDEX.read_text())
    harnesses = [ROOT / h for h in data.get("harnesses", [])]
    return harnesses


def main() -> None:
    report: Dict[str, List[Dict[str, object]]] = {"harnesses": []}
    for harness in load_harnesses():
        base = harness.stem  # e.g., instant_crash_afl
        func = derive_function_from_harness(harness)
        crashes = collect_crashes_for_harness(base)
        report["harnesses"].append(
            {
                "harness": harness.relative_to(ROOT).as_posix(),
                "function": func,
                "crashes": crashes,
            }
        )
    out_path = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else load_config(DEFAULT_OUTPUT)
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    total_crashes = sum(len(h["crashes"]) for h in report["harnesses"])
    print(f"[collect] Wrote crash summary to {out_path} (crashes: {total_crashes})")
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
