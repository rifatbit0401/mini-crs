# Mini CRS Vulnerable OSS-Fuzz Target

This repository is an intentionally unsafe C/C++ project laid out like an OSS-Fuzz target. It contains multiple bug classes (stack/heap buffer overflows, integer overflows, use-after-free, double-free, and unchecked format strings) to exercise automated analysis and patching workflows.

## Layout
- `src/` and `include/`: Vulnerable library code.
- `fuzz/`: LibFuzzer entrypoint that drives the vulnerable code.
- `build.sh`: OSS-Fuzz style build script that compiles the library and fuzzer.
- `Dockerfile` and `project.yaml`: Minimal OSS-Fuzz metadata.

## Known Bug Classes
- Stack and heap buffer overflows from unchecked copies and mis-sized allocations.
- Integer overflows that shrink allocations followed by large copies.
- Use-after-free and double-free sequences.
- Format string exposure and unchecked length parsing.

## Running the OSS-Fuzz Target
### Quick native build (no sanitizers)
You need `clang`/`clang++` and `libFuzzer` available via `LLVMFuzzer` environment variables.

```bash
clang -Iinclude -c src/vuln_lib.c -o vuln_lib.o
clang++ -std=c++17 -Iinclude fuzz/fuzz_target.cc vuln_lib.o -o vuln_fuzzer
# create a seed corpus directory and run
mkdir -p corpus
./vuln_fuzzer corpus/
```

### OSS-Fuzz-style container build/run
This repository already has the `Dockerfile`, `project.yaml`, and `build.sh` layout expected by OSS-Fuzz.

1) Clone the main [oss-fuzz](https://github.com/google/oss-fuzz) repo and place this project at `oss-fuzz/projects/mini-crs`.
2) From the `oss-fuzz` root, build the project image and fuzzer:
```bash
python3 infra/helper.py build_image mini-crs
python3 infra/helper.py build_fuzzers mini-crs --sanitizer address --engine libfuzzer
```
3) Run the fuzzer inside the helper harness (creates an output directory under `/tmp` by default):
```bash
python3 infra/helper.py run_fuzzer mini-crs vuln_fuzzer --corpus-dir ./corpus
```

The helper scripts mount this repo, set `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `LIB_FUZZING_ENGINE`, and `OUT`, and then execute `build.sh` to produce `out/vuln_fuzzer`.

### Standalone Docker image (no oss-fuzz checkout required)
Build a runnable image and point it at a corpus directory (mounted volume). The image builds the fuzzer in a builder stage and copies the binary into a minimal runtime stage.

```bash
# from ossfuzz-target/
docker build -t mini-crs-fuzz .

# run with a host corpus directory mounted into the container
mkdir -p corpus
docker run --rm -v "$(pwd)/corpus:/workspace/corpus" mini-crs-fuzz

# to pass a different corpus path inside the container:
docker run --rm -v "$(pwd)/corpus:/seeds" mini-crs-fuzz /seeds
```

The container entrypoint is `vuln_fuzzer`; the default corpus path is `/workspace/corpus`. AddressSanitizer is enabled in the build stage, so crashes will emit ASAN reports in the container logs.

### Quick build check helper
Use the included helper to verify the Dockerized build works (wraps `docker build`):

```bash
# from repo root (mini-crs/)
bash builder/check_build.sh                 # tags image as mini-crs-fuzz-check by default
IMAGE_TAG=my-tag bash builder/check_build.sh  # override the output tag
```
