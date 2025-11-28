# CodeQL Analysis

Run CodeQL against the target project using the helper script.

## Prerequisites
- CodeQL CLI installed and available as `codeql` (or set `CODEQL_BIN`).
- Clang toolchain available for the build command inside the database creation step.

## Usage
From the repo root:

```bash
bash code-ql/run_codeql.sh
```

This will:
- Create a CodeQL database at `code-ql/db` (deletes any previous DB there).
- Analyze with the `cpp-security-and-quality` suite.
- Emit SARIF results to `code-ql/findings.sarif`.

### Customization (env vars)
- `CODEQL_BIN`: path to the CodeQL CLI.
- `TARGET`: project root to scan (default `./ossfuzz-target`).
- `DB_DIR`: database directory (default `code-ql/db`).
- `RESULTS`: SARIF output path (default `code-ql/findings.sarif`).
- `QUERY_SUITE`: CodeQL suite/queries (default `/workspace/code-ql/queries` in the container).
- `SEARCH_PATH`: CodeQL search/library path (default `/opt/codeql` in the container).

### Custom queries bundled
Custom heuristics live in `code-ql/queries/`:
- `UnsafeCopy.ql`: memcpy/strcpy/strcat/sprintf without bounds awareness.
- `FormatStringLiteral.ql`: printf-family with non-literal format.
- `UseAfterFreeHint.ql`: heuristic use-after-free (variable used after free()).
- `AllocMultOverflow.ql`: malloc/realloc size uses multiplication (overflow risk).

The default `QUERY_SUITE` points at this directory so these run automatically; set `QUERY_SUITE` to another suite/pack if desired.

## Dockerized CodeQL
You can build a container that bundles the CodeQL CLI and this project. You must place a CodeQL CLI bundle tarball (e.g., `codeql-bundle-linux64.tar.gz` from GitHub releases) next to the Dockerfile and set `CODEQL_TARBALL` accordingly.

```bash
# from repo root, with a CodeQL bundle placed at code-ql/codeql-bundle.tar.gz
docker build -t mini-crs-codeql -f code-ql/Dockerfile code-ql \
  --build-arg CODEQL_ARCHIVE=codeql-bundle.zip   # name of the CodeQL zip you downloaded

# run analysis (override env vars as needed)
docker run --rm \
  -e TARGET=/workspace/ossfuzz-target \
  mini-crs-codeql

# to change output or query suite:
docker run --rm \
  -e TARGET=/workspace/ossfuzz-target \
  -e RESULTS=/workspace/code-ql/findings.sarif \
  -e QUERY_SUITE=cpp/ql/src/codeql-suites/cpp-security-and-quality.qls \
  mini-crs-codeql
```

The container copies the repo into `/workspace` and uses the included `code-ql/run_codeql.sh` as the entrypoint. SARIF results will be written inside the container at the path specified by `RESULTS` (default `/workspace/code-ql/findings.sarif`); mount a volume if you want to collect them on the host.
