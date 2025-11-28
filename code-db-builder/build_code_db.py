#!/usr/bin/env python3
"""
Quick-and-dirty code database builder for the ossfuzz-target project.

It scans source files and emits JSON describing files and their functions with
start/end line numbers. Intended to run from the repo root:

  python3 code-db-builder/build_code_db.py [path-to-project] [output-json]

Defaults to ../ossfuzz-target and writes to code-db-builder/code_db.json when
run from the repo root.
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional


ALLOWED_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "sizeof"}


def strip_comments(lines: List[str]) -> List[str]:
    """Remove // and /* */ comments for simple parsing."""
    stripped: List[str] = []
    in_block = False
    for line in lines:
        i = 0
        new_line = []
        while i < len(line):
            if not in_block and line.startswith("//", i):
                break  # rest of line is a comment
            if not in_block and line.startswith("/*", i):
                in_block = True
                i += 2
                continue
            if in_block and line.startswith("*/", i):
                in_block = False
                i += 2
                continue
            if in_block:
                i += 1
                continue
            new_line.append(line[i])
            i += 1
        stripped.append("".join(new_line))
    return stripped


def extract_functions(path: Path) -> List[Dict[str, int]]:
    """Return a list of functions with start/end line numbers for a file."""
    raw_lines = path.read_text().splitlines()
    lines = strip_comments(raw_lines)

    functions: List[Dict[str, int]] = []
    header_lines: List[str] = []
    header_start: Optional[int] = None
    brace_depth = 0
    current_name: Optional[str] = None
    current_start: Optional[int] = None

    for idx, line in enumerate(lines, start=1):
        # Collapse whitespace to help the regex.
        collapsed = line.strip()

        if brace_depth == 0:
            if not header_lines:
                header_start = idx
            header_lines.append(collapsed)

            if "{" in collapsed:
                header_text = " ".join(header_lines)
                # Skip likely non-function constructs.
                candidates = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", header_text)
                if not candidates:
                    header_lines.clear()
                    header_start = None
                    continue
                name = candidates[-1]
                if name in KEYWORDS:
                    header_lines.clear()
                    header_start = None
                    continue

                current_name = name
                current_start = header_start if header_start is not None else idx
                brace_depth = header_text.count("{") - header_text.count("}")
                header_lines.clear()
                header_start = None
                # Handle edge case: function with opening and closing brace on same line.
                if brace_depth == 0:
                    functions.append(
                        {
                            "name": current_name,
                            "start_line": current_start,
                            "end_line": idx,
                        }
                    )
                    current_name = None
                    current_start = None
                continue

            # Reset if we hit a declaration/statement ending in semicolon without a brace.
            if ";" in collapsed:
                header_lines.clear()
                header_start = None
        else:
            # Already inside a function; track braces.
            brace_depth += line.count("{")
            brace_depth -= line.count("}")
            if brace_depth <= 0 and current_name is not None and current_start is not None:
                functions.append(
                    {
                        "name": current_name,
                        "start_line": current_start,
                        "end_line": idx,
                    }
                )
                current_name = None
                current_start = None
                brace_depth = 0

    return functions


def build_db(root: Path) -> Dict[str, List[Dict[str, int]]]:
    files_info = []
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in ALLOWED_EXTS or not path.is_file():
            continue
        rel_path = path.relative_to(root)
        functions = extract_functions(path)
        files_info.append(
            {"path": str(rel_path), "functions": functions},
        )
    return {"project_root": str(root), "files": files_info}


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "ossfuzz-target"
    out_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else Path(__file__).resolve().parent / "code_db.json"
    )
    if not target.exists():
        sys.stderr.write(f"Target path does not exist: {target}\n")
        sys.exit(1)
    db = build_db(target)
    out_path.write_text(json.dumps(db, indent=2) + "\n")
    json.dump(db, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
