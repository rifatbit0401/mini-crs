#!/usr/bin/env python3
"""
Generate AFL++ harnesses for functions listed in the vulnerable_functions.json output.

Harnesses are written to fuzzer/harnesses/<function>_afl.c and include the
ossfuzz-target source directly so even static functions can be exercised.
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.yml"
DEFAULT_VULN_JSON = ROOT / "static-analyzer" / "vulnerable_functions.json"
DEFAULT_TARGET_SRC = ROOT / "ossfuzz-target" / "src" / "vuln_lib.c"
HARNESS_DIR = ROOT / "fuzzer" / "harnesses"
HARNESS_INDEX = ROOT / "fuzzer" / "harnesses.json"


def load_config() -> Dict[str, str]:
    cfg = {
        "vuln_output": str(DEFAULT_VULN_JSON),
        "target_src": str(DEFAULT_TARGET_SRC),
    }
    if CONFIG_PATH.exists():
        for line in CONFIG_PATH.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            if key.strip() == "vuln_output":
                cfg["vuln_output"] = value.strip()
            if key.strip() == "target_src":
                cfg["target_src"] = value.strip()
    return cfg


def sanitize_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def load_functions(vuln_json: Path) -> Set[str]:
    data = json.loads(vuln_json.read_text())
    funcs = {entry["function"] for entry in data if entry.get("function")}
    return funcs


def write_harness(func: str, rel_src: str) -> Path:
    HARNESS_DIR.mkdir(parents=True, exist_ok=True)
    fname = HARNESS_DIR / f"{sanitize_name(func)}_afl.c"
    content = f"""// Auto-generated AFL++ harness for {func}
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

// Pull in the implementation (includes static functions)
#include "{rel_src}"

#define MAX_INPUT (1 << 16)

int main(int argc, char **argv) {{
  uint8_t buf[MAX_INPUT];
  ssize_t len = 0;

  if (argc > 1) {{
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {{
      return 0;
    }}
    len = (ssize_t)fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
  }} else {{
    len = read(STDIN_FILENO, buf, sizeof(buf));
  }}

  if (len <= 0) {{
    return 0;
  }}

  {func}(buf, (size_t)len);
  return 0;
}}
"""
    fname.write_text(content)
    print(f"[harness] wrote {fname}")
    return fname


def main() -> None:
    cfg = load_config()
    vuln_json = Path(cfg["vuln_output"]).resolve()
    if not vuln_json.exists():
        raise SystemExit(f"[harness] vuln json not found: {vuln_json}")
    funcs = load_functions(vuln_json)
    target_src = Path(cfg["target_src"]).resolve()
    if not target_src.exists():
        raise SystemExit(f"[harness] target source not found: {target_src}")
    rel_include_from_harness = Path(
        Path(
            __import__("os").path.relpath(target_src, HARNESS_DIR)
        )
    ).as_posix()
    if not funcs:
        print("[harness] No functions found to generate harnesses for.")
        return
    written: List[str] = []
    for func in sorted(funcs):
        path = write_harness(func, rel_include_from_harness)
        written.append(str(path.relative_to(ROOT)))
    HARNESS_INDEX.write_text(json.dumps({"harnesses": written}, indent=2) + "\n")
    print(f"[harness] index written to {HARNESS_INDEX}")


if __name__ == "__main__":
    main()
